export const generatePIN = () => {
  return Math.floor(1000 + Math.random() * 9000).toString(); // PIN de 4 dígitos
};
