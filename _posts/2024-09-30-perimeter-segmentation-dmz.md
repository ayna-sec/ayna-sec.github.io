---
title: "Network Security: Perimeter vs Segmentation vs DMZ"
date: 2024-09-30T19:29:02-05:00
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - "network security"
  - notes
  - diagram
  - concepts
---

# Perimeter vs Segmentation vs DMZ

**Network security** is the protection of a network's integrity . There are many strategies for that. Some of these are the following:
<!--more-->

## Perimeter security

The network perimeter is the boundary of the network, separating it from the Internet, which is then defined as a Not-trusted Zone. The zone inside the network perimeter can be a Trusted Zone or not (there might me another subnet).

Some security tools that can be implemented on the network perimeter are:

- Firewalls.
  
- Routers.
  
- VPNs.
  
- Intrusion Detection & Prevention Systems (IDS/IPS).
  

## Network Segmentation

The process of network segmentation is the division of a network in logical segments with their own policy or security controls. These segments are then isolated from the other zones and enforce access control between them.

Some network segmentation's methods are VLANs and DMZs.

## DMZ

A DMZ (Demilitarized Zone) is a lightly protected subnet positioned between the internal network and the external internet or an internet-facing firewall. The DMZ normally hosts a public server (e.g. web server, mail server...) in an isolated network so it minimizes the risk of compromising the internal network.

## Recap and diagram

The next diagram shows the interaction between the previous concepts.

![diagram](/assets/images/dmz-perimeter-segments-diagram.png){: .align-full}

| Security perimeter | Network segmentation | DMZ | Intranet |
| --- | --- | --- | --- |
| It separates our network from the Internet | It divides the network into subnets. | A subnet facing the Internet. | Trusted private network. |
