from sage.all import *
print 'here'
M = MatrixSpace(GF(2), 3, 4)
V = VectorSpace(GF(2), 3)
A = M([[1, 0, 1, 1], [0, 1, 1, 0], [1, 1, 0, 0]])
goal = V([1, 1, 1])
print A.solve_right(goal)
