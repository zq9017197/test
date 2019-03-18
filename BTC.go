package main

import "fmt"

func main() {
	total := 2100.0       // 比特币总数
	rewardCount := 50.0   // 奖励 BTC 的数量
	blockInterval := 21.0 // 区块间隔，单位万
	reduceCount := 0      //减半次数
	year := 2009
	for total > 0.1 {
		// 在区块间隔内，统一奖励（生成）rewardCount 个比特币
		// 类型转换
		sum := blockInterval * rewardCount
		total -= sum
		by := year
		year += 4
		fmt.Println("总量：", total, "；", by, " ~ ", year, "年挖出：", sum, "；奖励：", rewardCount)

		// 每挖到 21w 个矿，奖励减半
		rewardCount *= 0.5
		reduceCount++
	}
}
