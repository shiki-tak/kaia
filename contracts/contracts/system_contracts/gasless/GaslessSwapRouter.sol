// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "./IWKAIA.sol";

contract GaslessSwapRouter {
    IUniswapV2Router02 public immutable uniswapRouter;
    IUniswapV2Factory public immutable uniswapFactory;
    IWKAIA public immutable WKAIA;

    event SwapExecuted(
        address indexed token,
        uint256 amountIn,
        uint256 amountOut
    );
    event WKAIAUnwrapped(uint256 indexed amount);
    event KAIAReceived(uint256 indexed amount);
    event GasRepaid(address indexed proposer, uint256 amount);

    error InsufficientSwapOutput(uint256 expected, uint256 actual);

    constructor(
        address _uniswapRouter,
        address _uniswapFactory,
        address _wkaia
    ) {
        uniswapRouter = IUniswapV2Router02(_uniswapRouter);
        uniswapFactory = IUniswapV2Factory(_uniswapFactory);
        WKAIA = IWKAIA(_wkaia);
    }

    function swapForGas(
        address token,
        uint256 amountIn,
        uint256 amountOut,
        uint256 amountRepay
    ) external {
        require(amountIn > 0, "Invalid amount");
        require(amountOut > amountRepay, "Invalid repay amount");

        IERC20(token).transferFrom(msg.sender, address(this), amountIn);
        IERC20(token).approve(address(uniswapRouter), amountIn);

        // Prepare swap parameters
        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = address(WKAIA);

        // Run swap to convert to WAKAIA
        uint256[] memory amounts = uniswapRouter.swapExactTokensForTokens(
            amountIn,
            amountOut,
            path,
            address(this),
            block.timestamp + 300
        );

        uint256 receivedAmount = amounts[1];
        
        if (receivedAmount < amountOut + amountRepay) {
            revert InsufficientSwapOutput(amountOut + amountRepay, receivedAmount);
        }

        // Withdraw WKAIA to KAIA
        WKAIA.withdraw(receivedAmount);

        // Pay to proposer
        (bool success, ) = block.coinbase.call{value: amountRepay}("");
        require(success, "Failed to send KAIA to proposer");

        // Send the remaining amount to the user
        uint256 remainingAmount = receivedAmount - amountRepay;
        (bool userTransferSuccess, ) = msg.sender.call{value: remainingAmount}("");
        require(userTransferSuccess, "Failed to send remaining KAIA to user");

        emit SwapExecuted(token, amounts[0], amounts[1]);
        emit WKAIAUnwrapped(receivedAmount);
        emit KAIAReceived(receivedAmount);
        emit GasRepaid(block.coinbase, amountRepay);
    }

    receive() external payable {
        emit KAIAReceived(msg.value);
    }
}
