// A JS file that uses regex .exec() heavily — must NOT be read as code execution.
function tokenize(str, re) {
  let m;
  const tokens = [];
  while ((m = re.exec(str)) !== null) {
    tokens.push(m[1]);
  }
  return tokens;
}

// This module's job is to detect the string 'eval(' in other code — the literal
// below is a detection signature, not a live call.
const DANGEROUS_SIGNATURES = ['eval(', 'exec(', 'child_process'];
