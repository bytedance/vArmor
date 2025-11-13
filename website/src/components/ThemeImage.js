import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';

const ThemeImage = ({ lightSrc, darkSrc, alt, width = '100%' }) => {
  return (
    <BrowserOnly fallback={<div>Loading image...</div>}>
      {() => {        
        const theme = document.documentElement.getAttribute('data-theme');
        const src = theme === 'dark' ? darkSrc : lightSrc;
        const imgStyle = {width: width, height: 'auto', maxWidth: '100%', display: 'block', margin: '0 auto'};
        return (
          <div style={{ textAlign: 'center' }}>
            <img src={src} alt={alt} style={imgStyle} />
          </div>
        );
      }}
    </BrowserOnly>
  );
};

export default ThemeImage;
