from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import motor.motor_asyncio
import os


# --- Settings and Globals ---


# PUBLIC_INTERFACE
class Settings(BaseModel):
    """App settings loaded from environment."""

    mongodb_url: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    mongodb_db: str = os.getenv("MONGODB_DB", "tic_tac_toe")
    jwt_secret: str = os.getenv("JWT_SECRET_KEY", "supersecretkey")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 120


settings = Settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Tic Tac Toe Backend API",
    version="1.0.0",
    description=(
        "Backend API for Tic Tac Toe game with authentication, game logic, and real-time updates."
    )
)

origins = ["*"]  # Adjust for production

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB async client
client = motor.motor_asyncio.AsyncIOMotorClient(settings.mongodb_url)
db = client[settings.mongodb_db]


# --- Models ---


# PUBLIC_INTERFACE
class Token(BaseModel):
    access_token: str
    token_type: str


# PUBLIC_INTERFACE
class TokenData(BaseModel):
    username: Optional[str] = None


# PUBLIC_INTERFACE
class User(BaseModel):
    username: str = Field(..., description="User's public username")
    email: EmailStr = Field(..., description="E-mail (unique)")
    disabled: Optional[bool] = False


# PUBLIC_INTERFACE
class UserInDB(User):
    hashed_password: str


# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=24)
    email: EmailStr
    password: str = Field(..., min_length=6)


# PUBLIC_INTERFACE
class GameCreate(BaseModel):
    room_name: str = Field(..., description="Friendly room name")


# PUBLIC_INTERFACE
class JoinGameRequest(BaseModel):
    room_id: str


# PUBLIC_INTERFACE
class MoveRequest(BaseModel):
    game_id: str
    x: int = Field(..., ge=0, le=2)
    y: int = Field(..., ge=0, le=2)


# PUBLIC_INTERFACE
class GameState(BaseModel):
    board: List[List[str]] = Field(..., description="3x3 board (X, O, or '')")
    turn: str = Field(..., description="player (username) whose turn it is")
    winner: Optional[str] = Field(default=None, description="username of the winner, if any")
    draw: bool = Field(default=False, description="whether game ended in draw")
    game_id: str
    opponent: Optional[str] = None
    players: List[str]
    started: bool = False


# --- Auth Utils ---


# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Check that the plaintext password matches the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


# PUBLIC_INTERFACE
def get_password_hash(password):
    """Hash a password for storing in the db."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
async def get_user(username: str) -> Optional[UserInDB]:
    """Retrieve a user from the MongoDB database by username."""
    user = await db.users.find_one({"username": username})
    return UserInDB(**user) if user else None


# PUBLIC_INTERFACE
async def authenticate_user(username: str, password: str):
    """Check username/password for login."""
    user = await get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate a JWT for a user."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.algorithm)


# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get the current logged-in user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate JWT credentials. Please login again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# --- User Route Handlers ---


@app.post(
    "/register",
    response_model=User,
    summary="Register a new user",
    tags=["Auth"],
)
async def register_user(user_in: UserCreate):
    """Create a new user account. Fails if username or email is already taken."""
    if await db.users.find_one({"username": user_in.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    if await db.users.find_one({"email": user_in.email}):
        raise HTTPException(status_code=400, detail="E-mail already taken")
    hashed_pw = get_password_hash(user_in.password)
    user = UserInDB(
        **user_in.model_dump(exclude={"password"}),
        hashed_password=hashed_pw,
    )
    await db.users.insert_one(user.model_dump())
    return User(**user.model_dump())


@app.post(
    "/token",
    response_model=Token,
    summary="Login for access token",
    tags=["Auth"],
)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate and return a JWT bearer token."""
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get(
    "/users/me",
    summary="Get current user",
    tags=["Auth"],
)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get information about the currently authenticated user."""
    return current_user


# --- Tic Tac Toe Game Logic & Handlers ---


def empty_board():
    """Utility: returns empty tic tac toe board."""
    return [["", "", ""], ["", "", ""], ["", "", ""]]


def get_winner(board: List[List[str]]) -> Optional[str]:
    """Check if there is a winner ('X' or 'O'), else None."""
    lines = board + [list(x) for x in zip(*board)]
    lines.append([board[i][i] for i in range(3)])  # diag
    lines.append([board[i][2 - i] for i in range(3)])  # anti-diag
    for line in lines:
        if line[0] and line.count(line[0]) == 3:
            return line[0]
    return None


def board_full(board: List[List[str]]) -> bool:
    """Is the board full?"""
    return all(cell for row in board for cell in row)


@app.post(
    "/games",
    response_model=GameState,
    summary="Create a new game",
    tags=["Game"],
)
async def create_game(
    game_in: GameCreate, current_user: User = Depends(get_current_user)
):
    """Create a new tic tac toe game (room/board), user becomes X and first player."""
    board = empty_board()
    doc = {
        "board": board,
        "players": [current_user.username],
        "room_name": game_in.room_name,
        "started": False,
        "turn": current_user.username,
        "winner": None,
        "draw": False,
        "created_at": datetime.utcnow(),
    }
    result = await db.games.insert_one(doc)
    game_id = str(result.inserted_id)
    return GameState(
        board=board,
        turn=current_user.username,
        winner=None,
        draw=False,
        game_id=game_id,
        players=[current_user.username],
        started=False,
    )


@app.post(
    "/games/join",
    response_model=GameState,
    summary="Join a game",
    tags=["Game"],
)
async def join_game(
    req: JoinGameRequest, current_user: User = Depends(get_current_user)
):
    """Join a game lobby (become O), only if one spot is free."""
    from bson import ObjectId
    game = await db.games.find_one({"_id": ObjectId(req.room_id)})
    if not game:
        raise HTTPException(404, detail="Game not found")
    if len(game["players"]) >= 2:
        raise HTTPException(400, detail="Game already has 2 players")
    if current_user.username in game["players"]:
        raise HTTPException(400, detail="Already joined")
    await db.games.update_one(
        {"_id": ObjectId(req.room_id)},
        {
            "$push": {"players": current_user.username},
            "$set": {"started": True},
        }
    )
    # Fetch updated game
    updated = await db.games.find_one({"_id": ObjectId(req.room_id)})
    opponent = (
        updated["players"][0]
        if updated["players"][1] == current_user.username
        else updated["players"][1]
    )
    return GameState(
        board=updated["board"],
        turn=updated["turn"],
        winner=updated.get("winner"),
        draw=updated.get("draw", False),
        game_id=req.room_id,
        players=updated["players"],
        started=True,
        opponent=opponent,
    )


@app.get(
    "/games",
    response_model=List[GameState],
    summary="List open games",
    tags=["Game"],
)
async def list_open_games(current_user: User = Depends(get_current_user)):
    """Return all games waiting for a second player (can be joined)."""
    games = []
    async for game in db.games.find({"started": False}):
        games.append(
            GameState(
                board=game["board"],
                turn=game["turn"],
                winner=game.get("winner"),
                draw=game.get("draw", False),
                game_id=str(game["_id"]),
                players=game.get("players", []),
                started=False,
            )
        )
    return games


@app.get(
    "/games/{game_id}",
    response_model=GameState,
    summary="Get game state",
    tags=["Game"],
)
async def get_game_state(game_id: str, current_user: User = Depends(get_current_user)):
    """Get current board, turn, and game info."""
    from bson import ObjectId
    game = await db.games.find_one({"_id": ObjectId(game_id)})
    if not game:
        raise HTTPException(404, detail="Game not found")
    if current_user.username not in game["players"]:
        raise HTTPException(403, detail="You are not a player in this game")
    opponent = (
        game["players"][0]
        if game["players"][1] == current_user.username
        else game["players"][1]
    ) if len(game["players"]) == 2 else None
    return GameState(
        board=game["board"],
        turn=game["turn"],
        winner=game.get("winner"),
        draw=game.get("draw", False),
        game_id=game_id,
        players=game.get("players", []),
        started=game.get("started", False),
        opponent=opponent,
    )


@app.post(
    "/games/move",
    response_model=GameState,
    summary="Make a move",
    tags=["Game"],
)
async def make_move(
    move: MoveRequest, current_user: User = Depends(get_current_user)
):
    """
    Make a move in a specified game (returns new board state and notifies via WebSocket if another
    player is connected).
    """
    from bson import ObjectId
    game = await db.games.find_one({"_id": ObjectId(move.game_id)})
    if not game:
        raise HTTPException(404, detail="Game not found")
    if not game["started"]:
        raise HTTPException(400, detail="Game not started")
    if current_user.username not in game["players"]:
        raise HTTPException(403, detail="Not a player in this game")
    symbol = "X" if current_user.username == game["players"][0] else "O"
    if current_user.username != game["turn"]:
        raise HTTPException(400, detail="Not your turn")
    board = [row[:] for row in game["board"]]
    if board[move.x][move.y]:
        raise HTTPException(400, detail="Cell already taken")

    board[move.x][move.y] = symbol
    winner_symbol = get_winner(board)
    winner = None
    draw = False
    if winner_symbol:
        winner = current_user.username
    elif board_full(board):
        draw = True

    # Set next turn
    players = game["players"]
    next_turn = (
        players[1] if current_user.username == players[0] else players[0]
    ) if not (winner or draw) else None

    await db.games.update_one(
        {"_id": ObjectId(move.game_id)},
        {
            "$set": {
                "board": board,
                "turn": next_turn,
                "winner": winner,
                "draw": draw,
            }
        }
    )
    updated = await db.games.find_one({"_id": ObjectId(move.game_id)})

    # WebSocket logic: notify game watchers
    await notify_game_watchers(
        game_id=move.game_id,
        data={
            "type": "move",
            "state": GameState(
                board=updated["board"],
                turn=updated["turn"],
                winner=updated.get("winner"),
                draw=updated.get("draw", False),
                game_id=move.game_id,
                players=updated.get("players", []),
                started=updated.get("started", False),
            ).model_dump(),
        }
    )

    opponent = (
        updated["players"][0]
        if updated["players"][1] == current_user.username
        else updated["players"][1]
    ) if len(updated["players"]) == 2 else None

    return GameState(
        board=updated["board"],
        turn=updated["turn"],
        winner=updated.get("winner"),
        draw=updated.get("draw", False),
        game_id=move.game_id,
        players=updated.get("players", []),
        started=updated.get("started", False),
        opponent=opponent,
    )


@app.get(
    "/games/me",
    response_model=List[GameState],
    summary="List my games",
    tags=["Game"],
)
async def list_my_games(current_user: User = Depends(get_current_user)):
    """List all games the current user is a player in."""
    games = []
    async for game in db.games.find({"players": current_user.username}):
        games.append(
            GameState(
                board=game["board"],
                turn=game["turn"],
                winner=game.get("winner"),
                draw=game.get("draw", False),
                game_id=str(game["_id"]),
                players=game.get("players", []),
                started=game.get("started", False),
            )
        )
    return games


@app.get(
    "/games/history",
    response_model=List[GameState],
    summary="Get recent game results",
    tags=["Game"],
)
async def get_history(current_user: User = Depends(get_current_user)):
    """List finished games for the current user."""
    games = []
    async for game in db.games.find(
        {"players": current_user.username, "winner": {"$ne": None}}
    ):
        games.append(
            GameState(
                board=game["board"],
                turn=game["turn"],
                winner=game.get("winner"),
                draw=game.get("draw", False),
                game_id=str(game["_id"]),
                players=game.get("players", []),
                started=game.get("started", False),
            )
        )
    return games


# --- Real-Time Update WebSocket ---


WS_CONNECTIONS: Dict[str, List[WebSocket]] = {}  # game_id -> list of websockets


# PUBLIC_INTERFACE
async def notify_game_watchers(game_id: str, data: Dict[str, Any]):
    """Send data to all WebSocket clients watching this game."""
    conns = WS_CONNECTIONS.get(game_id, [])
    to_remove = []
    for ws in conns:
        try:
            await ws.send_json(data)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        conns.remove(ws)
    if not conns:
        WS_CONNECTIONS.pop(game_id, None)


@app.websocket("/ws/game/{game_id}")
async def websocket_gameboard(websocket: WebSocket, game_id: str):
    """
    WebSocket: get real-time updates for a game state.
    OperationId: websocketGameUpdates
    Summary: Real-time updates for a tic tac toe game.
    Send/receive JSON payloads for moves, listen for opponent moves and results.
    """
    await websocket.accept()
    if game_id not in WS_CONNECTIONS:
        WS_CONNECTIONS[game_id] = []
    WS_CONNECTIONS[game_id].append(websocket)
    try:
        while True:
            await websocket.receive_json()
    except WebSocketDisconnect:
        WS_CONNECTIONS[game_id].remove(websocket)
        if not WS_CONNECTIONS[game_id]:
            del WS_CONNECTIONS[game_id]
    except Exception:
        if game_id in WS_CONNECTIONS and websocket in WS_CONNECTIONS[game_id]:
            WS_CONNECTIONS[game_id].remove(websocket)


@app.get(
    "/ws/docs",
    tags=["Game"],
    summary="WebSocket usage help",
    operation_id="websocketHelp",
)
async def websocket_info():
    """Get documentation on websocket endpoint usage for the frontend."""
    return {
        "websocket_endpoint": "/ws/game/{game_id}",
        "payload": (
            "No payload required; this WebSocket pushes board state JSON updates to clients."
        ),
        "docs": (
            "Connect to /ws/game/{game_id} to receive real-time JSON updates when the board "
            "changes or a move is made. You do not need to send messages."
        ),
    }


@app.get("/", tags=["Health"])
async def health_check():
    """Health check for the backend API."""
    return {"message": "Healthy"}
