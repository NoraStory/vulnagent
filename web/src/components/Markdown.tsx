import { memo } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

// 组件映射固定为模块常量，避免每次渲染重建导致 react-markdown 重新解析整棵语法树
const components: Components = {
  h1: ({ children }) => <h3 className="mb-1.5 mt-3 text-[14px] font-semibold text-ink">{children}</h3>,
  h2: ({ children }) => <h3 className="mb-1.5 mt-3 text-[13.5px] font-semibold text-ink">{children}</h3>,
  h3: ({ children }) => <h4 className="mb-1 mt-2.5 text-[13px] font-semibold text-ink">{children}</h4>,
  p: ({ children }) => <p className="my-1.5 first:mt-0 last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="my-1.5 list-disc space-y-1 pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="my-1.5 list-decimal space-y-1 pl-5">{children}</ol>,
  li: ({ children }) => <li className="pl-0.5">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
  code: ({ children }) => (
    <code className="mono rounded-[5px] bg-subtle px-1 py-0.5 text-[11.5px] text-ink2">{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="mono my-2 overflow-x-auto rounded-[8px] border border-line bg-subtle p-2.5 text-[11.5px] leading-[18px] text-ink2 [&>code]:bg-transparent [&>code]:p-0">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-2 overflow-x-auto">
      <table className="w-full border-collapse text-[12px]">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-line bg-subtle px-2 py-1 text-left font-medium text-ink2">{children}</th>
  ),
  td: ({ children }) => <td className="border border-line px-2 py-1 align-top">{children}</td>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noreferrer noopener" className="text-brand underline decoration-brand/30">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-2 border-l-2 border-lineStrong pl-2.5 text-ink2">{children}</blockquote>
  ),
  hr: () => <hr className="my-3 border-line" />
};

// Markdown 渲染助手回复：只允许安全的内联语法，不解析原始 HTML。
// 用 memo 包裹，流式输出结束后的历史消息不再重复解析。
export const Markdown = memo(function Markdown({ content }: { content: string }) {
  return (
    <div className="text-[13px] leading-[21px] text-ink">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
});
