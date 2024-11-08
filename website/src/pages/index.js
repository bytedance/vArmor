// src/pages/index.js

import React from 'react';
import clsx from 'clsx';
import Layout from '@theme/Layout';
import styles from './index.module.css';
import Link from '@docusaurus/Link';
import { Analytics } from "@vercel/analytics/react"
function HomepageHeader() {
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      
      <div className="container">
        <h1 className="hero__title">vArmor</h1>
        <p className="hero__subtitle">
          Cloud-native container sandbox system for Kubernetes security.
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="https://github.com/bytedance/vArmor">
            View on GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

function Feature({ title, description }) {
  return (
    <div className={clsx('col col--4')}>
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
        <div className="row">
          <Feature
            title="Enhanced Security"
            description="Leverages Linux technologies like AppArmor, BPF, and Seccomp to harden containers."
          />
          <Feature
            title="Cloud Native"
            description="Integrates seamlessly with Kubernetes, providing powerful sandboxing mechanisms through CRDs."
          />
          <Feature
            title="Quick Deployment"
            description="Manage vArmor with Helm, and apply policies with built-in rules that are ready to use out of the box."
          />
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
        <section className="container">
          <div className="row">
            <div className="col col--12">
              <h2>License</h2>
              <p>
                vArmor is licensed under Apache 2.0. The eBPF code is located at vArmor-ebpf and is GPL-2.0 licensed.
              </p>
            </div>
          </div>
        </section>
        <section className="container">
          <div className="row">
            <div className="col col--12">
              <h2>Credits</h2>
              <p>
                Uses cilium/ebpf for eBPF management. References parts of kyverno code by Nirmata.
              </p>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
