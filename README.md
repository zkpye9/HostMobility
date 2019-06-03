# Host Mobility

This project explores solutions of supporting host mobility. We propose a proxy-based solution
to handle this problem. The goal is to establish a session between the client and the
server, so that after changing the server’s IP address, the same connection session
still works. This solution works with all applications and transport protocols, and
does not require to change applications. Key concepts in our design include the use
of UDP tunnels and a sequence of private IP addresses to uniquely identify a host.
We also implement a simple and incrementally deployable change to DNS as a
mechanism to learn the address.

## Getting Started

This project means to facilitate the following article:
https://repository.arizona.edu/handle/10150/625259

For more details related to design and implementation,
please check out the article.

## Authors

* **Kunpeng Zhang**

## License

This project is licensed under the MIT License.

## Acknowledgments

* I am grateful to Dr.Beichuan Zhang for his work on this research project and being my honors thesis advisor.
