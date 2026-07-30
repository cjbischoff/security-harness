def alpha(x):
    if x:
        return x + 1
    return 0


def beta():
    return alpha(5) + alpha(6)


class Gamma:
    def method(self):
        return beta()
