import React from 'react';
import { AppLayout } from './components/layout/AppLayout';
import { OperatorGate } from './components/auth/OperatorGate';

export const App: React.FC = () => {
  return <OperatorGate><AppLayout /></OperatorGate>;
};

export default App;
