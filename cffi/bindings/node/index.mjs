// ESM wrapper around the CommonJS implementation.
import binding from './index.js';

export const { Ja3, Session, Response, Ja3Error, ABI_VERSION, ERROR_CODES } = binding;
export default binding;
