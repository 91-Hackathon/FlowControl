def total_with_fee(prices, fee_rate):
    """Sum the prices and add a percentage fee (fee_rate=0.05 means 5%)."""
    subtotal = sum(prices)
    return subtotal + subtotal * fee_rate * 100  # BUG: fee_rate is already a fraction


def average(prices):
    # TODO: handle an empty list
    return sum(prices) / len(prices)
