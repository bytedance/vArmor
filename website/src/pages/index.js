// src/pages/index.js

import React from 'react';
import clsx from 'clsx';
import Layout from '@theme/Layout';
import styles from './index.module.css';
import Link from '@docusaurus/Link';
import Translate, {translate} from '@docusaurus/Translate';
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
              <Translate id="homepage.hero.tagline">
                Cloud-native container hardening for Kubernetes — from syscall to protocol, from workload to AI Agent.
              </Translate>
            </p>
            <div className={styles.buttons}>
              <Link
                className={clsx("button button--lg", styles.primaryButton)}
                to="/docs/main/introduction">
                <Translate id="homepage.hero.getStarted">Get Started</Translate>
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
    <div className={clsx('col col--3', styles.featureItem)}>
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
          <h2><Translate id="homepage.features.title">Core Features</Translate></h2>
          <p><Translate id="homepage.features.subtitle">Multiple enforcers, flexible policies, ready for production</Translate></p>
        </div>
        <div className="row">
          <Feature
            title={<Translate id="homepage.features.cloudNative.title">Cloud-Native</Translate>}
            description={<Translate id="homepage.features.cloudNative.description">Follows the Kubernetes Operator design pattern, allowing users to harden specific workloads by manipulating the CRD API.</Translate>}
            icon={<img src="/img/icon-cloud.svg" alt="Cloud-Native Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.multipleEnforcers.title">Multiple Enforcers</Translate>}
            description={<Translate id="homepage.features.multipleEnforcers.description">Provides AppArmor, BPF, Seccomp, and NetworkProxy enforcers that can be used individually or combined to control file access, process execution, network egress, and syscalls.</Translate>}
            icon={<img src="/img/icon-enforcer.svg" alt="Multiple Enforcers Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.networkProxy.title">Network Proxy</Translate>}
            description={<Translate id="homepage.features.networkProxy.description">Transparently intercepts container egress traffic via an Envoy sidecar, enabling L4/L7/TLS SNI access control with audit logging and dynamic policy updates — no Pod restart required.</Translate>}
            icon={<img src="/img/icon-network-proxy.svg" alt="Network Proxy Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.aiAgent.title">AI Agent Protection</Translate>}
            description={<Translate id="homepage.features.aiAgent.description">Defense-in-depth for AI Agent workloads — enforce access control from syscalls to network protocols, mitigating prompt injection-induced tool abuse and data exfiltration.</Translate>}
            icon={<img src="/img/icon-ai-agent.svg" alt="AI Agent Protection Icon" className={styles.featureIcon}/>}
          />
        </div>
        <div className="row">
          <Feature
            title={<Translate id="homepage.features.allowByDefault.title">Allow-by-Default</Translate>}
            description={<Translate id="homepage.features.allowByDefault.description">Only explicitly declared behaviors will be blocked, which effectively minimizes performance impact and enhances usability.</Translate>}
            icon={<img src="/img/icon-allow.svg" alt="Allow-by-Default Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.denyByDefault.title">Deny-by-Default</Translate>}
            description={<Translate id="homepage.features.denyByDefault.description">Enforces an allowlist policy where only explicitly permitted behaviors are allowed, providing the strongest security posture for sensitive workloads.</Translate>}
            icon={<img src="/img/icon-deny.svg" alt="Deny-by-Default Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.builtinRules.title">Built-in Rules</Translate>}
            description={<Translate id="homepage.features.builtinRules.description">Features a range of built-in rules ready to use out of the box, eliminating the need for expertise in security profile creation.</Translate>}
            icon={<img src="/img/icon-rules.svg" alt="Built-in Rules Icon" className={styles.featureIcon}/>}
          />
          <Feature
            title={<Translate id="homepage.features.behaviorModeling.title">Behavior Modeling</Translate>}
            description={<Translate id="homepage.features.behaviorModeling.description">Supports behavior modeling for workloads to develop allowlist profiles and guide configurations to adhere to least privilege.</Translate>}
            icon={<img src="/img/icon-model.svg" alt="Behavior Modeling Icon" className={styles.featureIcon}/>}
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
          <h2><Translate id="homepage.architecture.title">Architecture</Translate></h2>
          <p><Translate id="homepage.architecture.subtitle">How vArmor protects your workloads</Translate></p>
        </div>
        <div className={styles.architectureContent}>
          <div className={styles.architectureImage}>
            <ThemeImage 
              lightSrc="/img/architecture.svg" 
              darkSrc="/img/architecture-dark.svg" 
              alt="vArmor Architecture" 
            />
          </div>
          <div className={styles.architectureText}>
            <p>
              <Translate id="homepage.architecture.text1">
                vArmor primarily consists of two components: the Manager and the Agent. The Manager is responsible for responding to and managing policy objects, while the Agent handles the management of enforcers and profiles on Nodes.
              </Translate>
            </p>
            <p>
              <Translate id="homepage.architecture.text2">
                vArmor also supports the NetworkProxy enforcer, which injects an Envoy sidecar proxy and an init container into target Pods via the mutation webhook. The init container sets up iptables rules to redirect egress traffic to the Envoy sidecar, which then enforces L4/L7 access control policies generated by the Manager and delivered via ConfigMap.
              </Translate>
            </p>
            <p>
              <Translate id="homepage.architecture.text3">
                With VarmorPolicy or VarmorClusterPolicy objects, users can harden specific workloads and decide which enforcers and rules to use. The ArmorProfile CR acts as an internal interface used for profile management.
              </Translate>
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
          <h2><Translate id="homepage.quickStart.title">Quick Start</Translate></h2>
          <p><Translate id="homepage.quickStart.subtitle">Get up and running in minutes</Translate></p>
        </div>
        <div className={styles.quickStartSteps}>
          <div className={styles.quickStartStep}>
            <h3><Translate id="homepage.quickStart.step1.title">1. Fetch chart</Translate></h3>
            <CodeBlock language="bash">
              helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.10.0
            </CodeBlock>
          </div>
          <div className={styles.quickStartStep}>
            <h3><Translate id="homepage.quickStart.step2.title">2. Install</Translate></h3>
            <CodeBlock language="bash">
              helm install varmor varmor-0.10.0.tgz --namespace varmor --create-namespace --set image.registry="elkeid-ap-southeast-1.cr.volces.com"
            </CodeBlock>
          </div>
          <div className={styles.quickStartStep}>
            <h3><Translate id="homepage.quickStart.step3.title">3. Apply Policy</Translate></h3>
            <p>
              <Translate id="homepage.quickStart.step3.description">
                Create a VarmorPolicy to protect your workloads — supports AppArmor/BPF/Seccomp rules and NetworkProxy egress control
              </Translate>
            </p>
            <Link
              className="button button--primary"
              to="/docs/main/introduction#quick-start">
              <Translate id="homepage.quickStart.viewGuide">View Full Guide</Translate>
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
          <h2><Translate id="homepage.community.title">Community</Translate></h2>
          <p><Translate id="homepage.community.subtitle">Join the vArmor community</Translate></p>
        </div>
        <div className={styles.communityContent}>
          <div className={styles.communityItem}>
            <h3><Translate id="homepage.community.openSource.title">Open Source</Translate></h3>
            <p>
              <Translate id="homepage.community.openSource.description">
                vArmor was created by the Elkeid Team of the endpoint security department at ByteDance. The project is licensed under Apache 2.0 and is in active development.
              </Translate>
            </p>
            <Link
              className="button button--secondary"
              to="https://github.com/bytedance/vArmor">
              <Translate id="homepage.community.starOnGithub">Star on GitHub</Translate>
            </Link>
          </div>
          <div className={styles.communityItem}>
            <h3><Translate id="homepage.community.contribute.title">Contribute</Translate></h3>
            <p>
              <Translate id="homepage.community.contribute.description">
                We welcome contributions from the community! Whether it's reporting bugs, improving documentation, or adding new features, your help is appreciated.
              </Translate>
            </p>
            <Link
              className="button button--secondary"
              to="https://github.com/bytedance/vArmor/blob/main/docs/guides/development.md">
              <Translate id="homepage.community.contributionGuide">Contribution Guide</Translate>
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
      title={translate({id: 'homepage.layout.title', message: 'vArmor'})}
      description={translate({id: 'homepage.layout.description', message: 'Cloud-native container hardening for Kubernetes — from syscall to protocol, from workload to AI Agent.'})}>
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
