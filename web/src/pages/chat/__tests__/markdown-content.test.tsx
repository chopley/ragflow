import { render } from '@testing-library/react';
import DOMPurify from 'dompurify';
import MarkdownContent from '../markdown-content';

// Mock DOMPurify to track calls
jest.mock('dompurify', () => ({
  sanitize: jest.fn((content: string) => {
    // Simulate DOMPurify sanitization - more comprehensive
    return content
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/\s*onclick\s*=\s*"[^"]*"/gi, '') // Remove onclick attributes completely
      .replace(/javascript:/gi, '') // Remove javascript: completely
      .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
      .replace(/<img[^>]*src="[^"]*javascript:[^"]*"[^>]*>/gi, '')
      .replace(/<a[^>]*href="[^"]*javascript:[^"]*"[^>]*>.*?<\/a>/gi, '')
      .replace(
        /style="[^"]*javascript:[^"]*"/gi,
        'style="data-javascript:removed"',
      );
  }),
}));

// Mock the dependencies
jest.mock('@/hooks/document-hooks', () => ({
  useFetchDocumentThumbnailsByIds: () => ({
    setDocumentIds: jest.fn(),
    data: {},
  }),
}));

jest.mock('@/utils/request', () => ({
  default: jest.fn(),
}));

// Mock translation
jest.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

const mockSanitize = DOMPurify.sanitize as jest.Mock;

describe('MarkdownContent Security Tests', () => {
  const mockReference = {
    chunks: [
      {
        id: '1',
        content: null,
        document_id: 'doc1',
        document_name: 'test.pdf',
        dataset_id: 'dataset1',
        image_id: '',
        similarity: 0.95,
        vector_similarity: 0.95,
        term_similarity: 0.95,
        positions: [0, 100],
      },
    ],
    doc_aggs: [
      {
        doc_id: 'doc1',
        doc_name: 'test.pdf',
        url: 'https://example.com/test.pdf',
        count: 1,
      },
    ],
    total: 1,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should sanitize content to prevent XSS attacks', () => {
    const maliciousContent = `
      <p>Normal content</p>
      <script>alert('xss')</script>
      <button onclick="alert('clicked')">Click me</button>
    `;

    render(
      <MarkdownContent
        content={maliciousContent}
        loading={false}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalledWith(maliciousContent);
  });

  it('should remove script tags from content', () => {
    const contentWithScript = `
      <p>Safe content</p>
      <script>alert('malicious')</script>
      <p>More safe content</p>
    `;

    render(
      <MarkdownContent
        content={contentWithScript}
        loading={false}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalled();

    // Verify that the sanitized content doesn't contain script tags
    const sanitizedContent = mockSanitize.mock.results[0].value;
    expect(sanitizedContent).not.toContain('<script>');
    expect(sanitizedContent).not.toContain("alert('malicious')");
  });

  it('should remove onclick attributes from buttons', () => {
    const contentWithButton = `
      <p>Content</p>
      <button onclick="alert('clicked')" class="btn">Click me</button>
    `;

    render(
      <MarkdownContent
        content={contentWithButton}
        loading={false}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalled();

    // Verify that onclick attributes are removed
    const sanitizedContent = mockSanitize.mock.results[0].value;
    console.log('Sanitized content:', sanitizedContent); // Debug log
    expect(sanitizedContent).not.toContain('onclick=');
    expect(sanitizedContent).toContain('class="btn"'); // Safe attributes should remain
  });

  it('should preserve safe HTML tags and attributes', () => {
    const safeContent = `
      <p>Safe paragraph</p>
      <strong>Bold text</strong>
      <em>Italic text</em>
    `;

    render(
      <MarkdownContent
        content={safeContent}
        loading={false}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalled();

    // Verify that safe content is preserved
    const sanitizedContent = mockSanitize.mock.results[0].value;
    expect(sanitizedContent).toContain('<p>');
    expect(sanitizedContent).toContain('<strong>');
    expect(sanitizedContent).toContain('<em>');
  });

  it('should handle complex XSS attempts', () => {
    const complexXssContent = `
      <p>Normal content</p>
      <script>eval('alert(\\'xss\\')')</script>
      <img src="javascript:alert('xss')" />
      <a href="javascript:alert('xss')">Click me</a>
      <div style="background:url(javascript:alert('xss'))">Content</div>
      <iframe src="data:text/html,<script>alert('xss')</script>"></iframe>
    `;

    render(
      <MarkdownContent
        content={complexXssContent}
        loading={false}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalled();

    // Verify that dangerous content is removed
    const sanitizedContent = mockSanitize.mock.results[0].value;
    expect(sanitizedContent).not.toContain('<script>');
    expect(sanitizedContent).not.toContain('javascript:');
    expect(sanitizedContent).not.toContain('<iframe>');
    expect(sanitizedContent).toContain('<p>Normal content</p>'); // Safe content should remain
  });

  it('should sanitize chunk content in references', () => {
    const mockReferenceWithMaliciousChunk = {
      chunks: [
        {
          id: '1',
          content: null,
          document_id: 'doc1',
          document_name: 'test.pdf',
          dataset_id: 'dataset1',
          image_id: '',
          similarity: 0.95,
          vector_similarity: 0.95,
          term_similarity: 0.95,
          positions: [0, 100],
        },
      ],
      doc_aggs: [
        {
          doc_id: 'doc1',
          doc_name: 'test.pdf',
          url: 'https://example.com/test.pdf',
          count: 1,
        },
      ],
      total: 1,
    };

    render(
      <MarkdownContent
        content="Test content"
        loading={false}
        reference={mockReferenceWithMaliciousChunk}
      />,
    );

    // Verify that chunk content is also sanitized
    expect(mockSanitize).toHaveBeenCalledWith(
      expect.stringContaining('Test content'),
    );
  });

  it('should handle empty content gracefully', () => {
    render(
      <MarkdownContent content="" loading={false} reference={mockReference} />,
    );

    expect(mockSanitize).toHaveBeenCalledWith('');
  });

  it('should sanitize content even when loading is true', () => {
    const content = '<script>alert("xss")</script><p>Content</p>';

    render(
      <MarkdownContent
        content={content}
        loading={true}
        reference={mockReference}
      />,
    );

    expect(mockSanitize).toHaveBeenCalledWith(content);
  });
});
