import message from '@/components/ui/message';
import { Spin } from '@/components/ui/spin';
import request from '@/utils/request';
import classNames from 'classnames';
import DOMPurify from 'dompurify';
import mammoth from 'mammoth';
import { useEffect, useState } from 'react';
import { useGetDocumentUrl } from './hooks';

interface DocPreviewerProps {
  className?: string;
}

export const DocPreviewer: React.FC<DocPreviewerProps> = ({ className }) => {
  const url = useGetDocumentUrl();
  const [htmlContent, setHtmlContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const fetchDocument = async () => {
    setLoading(true);
    const res = await request(url, {
      method: 'GET',
      responseType: 'blob',
      onError: () => {
        message.error('Document parsing failed');
        console.error('Error loading document:', url);
      },
    });
    try {
      const arrayBuffer = await res.data.arrayBuffer();
      const result = await mammoth.convertToHtml(
        { arrayBuffer },
        { includeDefaultStyleMap: true },
      );

      const styledContent = result.value
        .replace(/<p>/g, '<p class="mb-2">')
        .replace(/<h(\d)>/g, '<h$1 class="font-semibold mt-4 mb-2">');

      // Sanitize the HTML content to prevent XSS attacks
      const sanitizedContent = DOMPurify.sanitize(styledContent, {
        ALLOWED_TAGS: [
          'p',
          'h1',
          'h2',
          'h3',
          'h4',
          'h5',
          'h6',
          'br',
          'strong',
          'em',
          'u',
          'ol',
          'ul',
          'li',
          'blockquote',
          'code',
          'pre',
        ],
        ALLOWED_ATTR: ['class', 'id', 'style'],
        KEEP_CONTENT: true,
      });

      setHtmlContent(sanitizedContent);
    } catch (err) {
      message.error('Document parsing failed');
      console.error('Error parsing document:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (url) {
      fetchDocument();
    }
  }, [url]);
  return (
    <div
      className={classNames(
        'relative w-full h-full p-4 bg-background-paper border border-border-normal rounded-md',
        className,
      )}
    >
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center">
          <Spin />
        </div>
      )}

      {!loading && <div dangerouslySetInnerHTML={{ __html: htmlContent }} />}
    </div>
  );
};
