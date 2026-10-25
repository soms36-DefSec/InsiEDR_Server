import { createContext, useContext } from 'react';

export const OperatorSignOutContext = createContext<(() => void) | null>(null);
export const useOperatorSignOut = () => useContext(OperatorSignOutContext);
