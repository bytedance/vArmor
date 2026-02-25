// src/pages/index.js

import React from 'react';
import clsx from 'clsx';
import Layout from '@theme/Layout';
import styles from './index.module.css';
import Link from '@docusaurus/Link';
import { Analytics } from "@vercel/analytics/react";
import ThemeImage from '@site/src/components/ThemeImage';
import CodeBlock from '@theme/CodeBlock';

function HomepageHeader() {
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className={styles.heroBgImage}></div>
      <div className="container">
        <div className={styles.heroContent}>
          <div className={styles.heroText}>
            <div className={styles.heroLogo}>
              <ThemeImage 
                lightSrc="/img/logo-white.svg" 
                darkSrc="/img/logo-white.svg" 
                alt="vArmor Logo" 
              />
            </div>
            <p className={styles.heroTagline}>
              Cloud-native container sandbox for Kubernetes
            </p>
            <div className={styles.buttons}>
              <Link
                className={clsx("button button--lg", styles.primaryButton)}
                to="/docs/main/introduction">
                Get Started
              </Link>
              <Link
                className={clsx("button button--lg", styles.primaryButton, "button--black")}
                to="https://github.com/bytedance/vArmor">
                GitHub
              </Link>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

function Feature({ title, description, icon }) {
  return (
    <div className={clsx('col col--4', styles.featureItem)}>
      <div className={styles.featureIcon}>
        {icon ? icon : <div className={styles.iconPlaceholder}></div>}
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className={styles.sectionTitle}>
          <h2>Core Features</h2>
          <p>Powerful capabilities to enhance your container security</p>
        </div>
        <div className="row">
          <Feature
            title="Cloud-Native"
            description="Follows the Kubernetes Operator design pattern, allowing users to harden specific workloads by manipulating the CRD API."
            icon={<img src="/img/icon-cloud.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />

          <Feature
            title="Multiple Enforcers"
            description="Abstracts AppArmor, BPF, and Seccomp as enforcers, supporting their use individually or in combination."
            icon={<img src="/img/icon-enforcer.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title="Allow-by-Default"
            description="Only explicitly declared behaviors will be blocked, which effectively minimizes performance impact and enhances usability."
            icon={<img src="/img/icon-allow.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
        </div>
        <div className="row">
          <Feature
            title="Built-in Rules"
            description="Features a range of built-in rules ready to use out of the box, eliminating the need for expertise in security profile creation."
            icon={<img src="/img/icon-rules.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title="Behavior Modeling"
            description="Supports behavior modeling for workloads to develop allowlist profiles and guide configurations to adhere to least privilege."
            icon={<img src="/img/icon-model.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title="Deny-by-Default"
            description="Capable of creating an allowlist profile from behavior models and ensuring only explicitly declared behaviors are permitted."
            icon={<img src="/img/icon-deny.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
        </div>
      </div>
    </section>
  );
}

function Architecture() {
  return (
    <section className={styles.architecture}>
      <div className="container">
        <div className={styles.sectionTitle}>
          <h2>Architecture</h2>
          <p>How vArmor works to protect your containers</p>
        </div>
        <div className={styles.architectureContent}>
          <div className={styles.architectureImage}>
            <ThemeImage 
              lightSrc="/img/architecture.svg" 
              darkSrc="/img/architecture-dark.svg" 
              alt="vArmor Architecture" 
              width="80%"
            />
          </div>
          <div className={styles.architectureText}>
            <p>
              vArmor primarily consists of two components: the Manager and the Agent. 
              The Manager is responsible for responding to and managing policy objects, 
              while the Agent handles the management of enforcers and profiles on Nodes.
            </p>
            <p>
              With VarmorPolicy or VarmorClusterPolicy objects, users can harden specific 
              workloads and decide which enforcers and rules to use. The ArmorProfile CR 
              acts as an internal interface used for profile management.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function QuickStart() {
  return (
    <section className={styles.quickStart}>
      <div className="container">
        <div className={styles.sectionTitle}>
          <h2>Quick Start</h2>
          <p>Get up and running in minutes</p>
        </div>
        <div className={styles.quickStartSteps}>
          <div className={styles.quickStartStep}>
            <h3>1. Fetch chart</h3>
            <CodeBlock language="bash">
              helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.9.2
            </CodeBlock>
          </div>
          <div className={styles.quickStartStep}>
            <h3>2. Install</h3>
            <CodeBlock language="bash">
              helm install varmor varmor-0.9.2.tgz --namespace varmor --create-namespace --set image.registry="elkeid-ap-southeast-1.cr.volces.com"
            </CodeBlock>
          </div>
          <div className={styles.quickStartStep}>
            <h3>3. Apply Policy</h3>
            <p>Create a VarmorPolicy to protect your workloads</p>
            <Link
              className="button button--primary"
              to="/docs/main/introduction#quick-start">
              View Full Guide
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

function Community() {
  return (
    <section className={styles.community}>
      <div className="container">
        <div className={styles.sectionTitle}>
          <h2>Community</h2>
          <p>Join the vArmor community</p>
        </div>
        <div className={styles.communityContent}>
          <div className={styles.communityItem}>
            <h3>Open Source</h3>
            <p>
              vArmor was created by the <strong>Elkeid Team</strong> of the endpoint security department at ByteDance. 
              The project is licensed under Apache 2.0 and is in active development.
            </p>
            <Link
              className="button button--secondary"
              to="https://github.com/bytedance/vArmor">
              Star on GitHub
            </Link>
          </div>
          <div className={styles.communityItem}>
            <h3>Contribute</h3>
            <p>
              We welcome contributions from the community! Whether it's reporting bugs, 
              improving documentation, or adding new features, your help is appreciated.
            </p>
            <Link
              className="button button--secondary"
              to="https://github.com/bytedance/vArmor/blob/main/docs/guides/development.md">
              Contribution Guide
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  return (
    <Layout
      title="vArmor - Container Security"
      description="Cloud-native container sandbox system designed to enhance container isolation and security in Kubernetes">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <Architecture />
        <QuickStart />
        <Community />
      </main>
      <Analytics />
    </Layout>
  );
}
