import sympy

if __name__ == "__main__":
  mat = sympy.Matrix([[1, 1, 1]], modulus=2)
  vec = sympy.Matrix([[1], [1], [1]], modulus=2)
  print mat*vec
