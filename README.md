# AYNA's Blog
Hi! I'm Angie Yuliana. I’m a cybersecurity specialist on a learning journey. And on this blog I'll share my projects and lessons learned.

## Cheatsheet for editing
### **Utility classes**:
- <ins>TEXT ALIGNMENT</ins> (add below the paragraph): `{: .text-left}` / `{: .text-center}` / `{: .text-right}` / `{: .text-justify}` / `{: .text-nowrap}`
- <ins>IMAGE ALIGNMENT</ins>: `![image-center](/assets/images/filename.jpg){: .align-center}` / `(...) {: .align-left}` / `(...) {: .align-right}` / for full image `[image]\n {: .align-full}`
- <ins>BUTTONS</ins>: `<a href="#" class="btn btn--primary">Link Text</a>`
  - Default `[Text](#link){: .btn}`
  - Primary `[Text](#link){: .btn .btn--primary}`
  - Success `[Text](#link){: .btn .btn--success}`
  - Warning `[Text](#link){: .btn .btn--warning}`
  - Danger `[Text](#link){: .btn .btn--danger}`
  - Info `[Text](#link){: .btn .btn--info}`
  - Inverse `[Text](#link){: .btn .btn--inverse}`
  - Light Outline `[Text](#link){: .btn .btn--light-outline}`
- <ins>CALL ACTIONS</ins> for block of text
  - Default `.notice`
  - Primary	`.notice--primary`
  - Info `.notice--info`
  - Warning	`.notice--warning`
  - Success	`.notice--success`
  - Danger `.notice--danger`
  - can also add the .notice class to a `<div>` element.
 
### **Post's front matter**
```yaml
---
title: "Welcome to Jekyll!"
date: 2019-04-18T15:34:30-04:00
categories:
  - blog
tags:
  - Jekyll
  - update
---
```
- To create a <ins>POST LINK</ins>, just add `link: url`:
- To create a <ins>MANUAL EXCERPT</ins>, add `excerpt_separator: "<!--more-->"` and put the separator after the excerpt.
- To update <ins>LAST EDITION TIME</ins>, add `last_modified_at: 2016-03-09T16:20:02-05:00`.

## Jekyll theme
[**Minimal Mistakes's Jekyll Theme**](https://github.com/mmistakes/mm-github-pages-starter/)

[Theme's Documentation](https://mmistakes.github.io/minimal-mistakes/docs/configuration/#skin)

[Icons](https://fontawesome.com/)
