
export function checkStrength (password: any): boolean {
  /* regex pattern to check for password strength:
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/
  RegExp Code for atleast 1 upper, lower, number & special character with min length 5
  */
  // if password is strong return true, else return false
  // eslint-disable-next-line no-useless-escape
  if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\-$*.{}?'"!@#%&\/\\,><:;|_~`^\]\[\)\(]).{5,}/.test(JSON.stringify(password))) {
    return true
  } else {
    return false
  }
}
