const rows = 10; // Number of rows in the grid
const cols = 10; // Number of columns in the grid
const mines = 20; // Number of mines

const grid = [];
let isFirstClick = true;
let gameOver = false;


// Function to create the grid
function createGrid(firstClickRow, firstClickCol) {
    for (let i = 0; i < rows; i++) {
        grid[i] = [];
        for (let j = 0; j < cols; j++) {
            grid[i][j] = {
                isMine: false,
                isOpen: false,
                isFlagged: false,
                count: 0,
            };
        }
    }

    // Generate mines after the first click
    if (isFirstClick) {
        isFirstClick = false;
        generateMines(firstClickRow, firstClickCol);
    }

    calculateAdjacentCounts();
}

// Function to generate mines after the first click
function generateMines(firstClickRow, firstClickCol) {
    let minesPlaced = 0;
    while (minesPlaced < mines) {
        const row = Math.floor(Math.random() * rows);
        const col = Math.floor(Math.random() * cols);
        if (!grid[row][col].isMine && !isAdjacentToFirstClick(row, col, firstClickRow, firstClickCol)) {
            grid[row][col].isMine = true;
            minesPlaced++;
        }
    }
}

// Function to check if a cell is adjacent to the first click
function isAdjacentToFirstClick(row, col, firstClickRow, firstClickCol) {
    const dx = Math.abs(row - firstClickRow);
    const dy = Math.abs(col - firstClickCol);
    return dx <= 1 && dy <= 1;
}

// Function to calculate adjacent mine counts
function calculateAdjacentCounts() {
    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
            if (!grid[i][j].isMine) {
                for (let x = -1; x <= 1; x++) {
                    for (let y = -1; y <= 1; y++) {
                        if (i + x >= 0 && i + x < rows && j + y >= 0 && j + y < cols) {
                            if (grid[i + x][j + y].isMine) {
                                grid[i][j].count++;
                            }
                        }
                    }
                }
            }
        }
    }
}



// Function to handle a left-click on a cell
// Function to handle a left-click on a cell
function handleLeftClick(row, col) {
    if (gameOver || grid[row][col].isOpen || grid[row][col].isFlagged) return;

    if (grid[row][col].isMine) {
        // Reveal all mines
        revealMines();
        gameOver = true;
        renderGrid(); // Render the grid with revealed mines
        document.getElementById('game-over').style.display = 'block'; // Show game over message
        return; // Exit the function to prevent further action
    } else {
        grid[row][col].isOpen = true;

        if (grid[row][col].count === 0) {
            openAdjacentCells(row, col);
        }

        if (checkWin()) {
            document.getElementById('game-over').textContent = 'Congratulations! You win!';
            document.getElementById('game-over').style.color = 'green'; // Change color for win message
            document.getElementById('game-over').style.display = 'block'; // Show win message
            gameOver = true;
            return; // Exit the function to prevent further action
        }
    }

    renderGrid();
}


// Function to open adjacent cells recursively
function openAdjacentCells(row, col) {
    if (grid[row][col].count === 0) {
        // Array to represent adjacent cell positions (top, right, bottom, left, top-right, top-left, bottom-right, bottom-left)
        const directions = [
            [-1, 0], [0, 1], [1, 0], [0, -1],
            [-1, 1], [-1, -1], [1, 1], [1, -1]
        ];

        // Iterate through adjacent cells
        for (const [dx, dy] of directions) {
            const newRow = row + dx;
            const newCol = col + dy;

            // Check if the adjacent cell is within the grid boundaries
            if (newRow >= 0 && newRow < rows && newCol >= 0 && newCol < cols) {
                // Check if the adjacent cell is not already open or flagged
                if (!grid[newRow][newCol].isOpen && !grid[newRow][newCol].isFlagged) {
                    grid[newRow][newCol].isOpen = true;

                    // Recursively open adjacent cells of the adjacent cell
                    openAdjacentCells(newRow, newCol);
                }
            }
        }
    }
}

// Function to handle a right-click on a cell (flagging/unflagging)
function handleRightClick(row, col) {
    if (gameOver || grid[row][col].isOpen) return;

    grid[row][col].isFlagged = !grid[row][col].isFlagged;
    renderGrid();
}

// Function to check if the player has won
function checkWin() {
    let allCellsOpened = true;

    // Iterate through all cells in the grid
    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
            // If a cell is not a mine and is not opened, the game is not won yet
            if (!grid[i][j].isMine && !grid[i][j].isOpen) {
                allCellsOpened = false;
                break;
            }
        }
    }

    return allCellsOpened;
}

// Function to reveal all mines when the game is over
function revealMines() {
    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
            if (grid[i][j].isMine) {
                grid[i][j].isOpen = true; // Reveal all mines
            }
        }
    }
}


// Function to reset the game
function resetGame() {
    isFirstClick = true;
    gameOver = false;
    document.getElementById('game-over').style.display = 'none'; // Hide the game over message
    revealMines();
    createGrid();
    renderGrid();
}




function renderGrid() {
    const minesweeperDiv = document.getElementById("minesweeper");
    minesweeperDiv.innerHTML = "";

    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
            const cell = document.createElement("div");
            cell.className = "cell";

            if (grid[i][j].isOpen) {
                cell.classList.add("open");
                if (grid[i][j].isMine) {
                    cell.classList.add("mine"); // Add "mine" class for revealed mines
                } else {
                    cell.textContent = grid[i][j].count || "";
                }
            } else if (grid[i][j].isFlagged) {
                cell.classList.add("flag");
            }

            cell.addEventListener("click", () => handleLeftClick(i, j));
            cell.addEventListener("contextmenu", (e) => {
                e.preventDefault();
                handleRightClick(i, j);
            });

            minesweeperDiv.appendChild(cell);
        }
    }
}









// Function to initialize the game (call this initially)
function initializeGame(firstClickRow, firstClickCol) {
    createGrid(firstClickRow, firstClickCol);
    renderGrid();
}

// Add an event listener to the reset button
document.getElementById('reset-button').addEventListener('click', resetGame);

// Call the function to initialize the game with the first click at row 3, col 5
initializeGame(3, 5);
