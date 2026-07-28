import React from 'react';
import Sidebar from './components/Sidebar';
import WorkflowBuilder from './components/WorkflowBuilder';

function App() {
  return (
    <div className="w-full h-screen flex flex-col bg-[#07090e] relative overflow-hidden select-none">
      <Sidebar />
      <WorkflowBuilder />
    </div>
  );
}

export default App;
