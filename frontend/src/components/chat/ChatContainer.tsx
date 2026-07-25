/** ChatContainer — Main chat container (messages + input). */
import { ReactNode } from "react";
interface ChatContainerProps { header: ReactNode; messages: ReactNode; input: ReactNode; sidebar?: ReactNode; }
export default function ChatContainer({ header, messages, input, sidebar }: ChatContainerProps) {
  return (
    <div className="h-screen flex flex-col bg-cerberus-dark">
      {header}
      <div className="flex-1 flex overflow-hidden">
        {sidebar && <div className="w-64 border-r border-cerberus-gray-700 hidden lg:block">{sidebar}</div>}
        <div className="flex-1 flex flex-col">
          <div className="flex-1 overflow-y-auto px-4 py-6 max-w-4xl mx-auto w-full">{messages}</div>
          <div className="border-t border-cerberus-gray-700 bg-cerberus-gray-900/80 px-4 py-3">{input}</div>
        </div>
      </div>
    </div>
  );
}
