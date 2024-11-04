import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';

const ThemeImage = ({ lightSrc, darkSrc, alt }) => {
  return (
    <BrowserOnly>
      {() => {
        const theme = document.documentElement.getAttribute('data-theme');
        const src = theme === 'dark' ? darkSrc : lightSrc;
        return <img src={src} alt={alt} style={{ maxWidth: '100%', height: 'auto' }} />;
      }}
    </BrowserOnly>
  );
};

export default ThemeImage;
