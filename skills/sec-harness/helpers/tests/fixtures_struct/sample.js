function alpha(x) {
  if (x) {
    return x + 1;
  }
  return 0;
}

const beta = () => {
  return alpha(5) + alpha(6);
};
