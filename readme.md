!["FAILS logo"](failslogo.svg)
# Fancy automated internet lecture system (**FAILS**) - components
[![Publish container](https://github.com/fails-components/ltihandler/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/fails-components/ltihandler/actions/workflows/docker-publish.yml)

This package is part of FAILS.
A web-based system developed out of university lectures.
It is a continuous pen-based notepad editor delivering **electronic chalk** to several beamers in the lecture hall.

The students can follow the lecture also on their tablets and notebooks and can scroll independently and ask questions to the lecturer using a chat function.
Furthermore, polls can be conducted.

After the lecture has been completed a pdf can be downloaded at any time.

FAILS components is completely integrated using LTI into LMS such as Moodle.

It is the reincarnation of a system, we are using at our theoretical physics institute for several years. Now *initial development* is almost complete, and the software is now rolling out next term university wide.

The system is written with containerization and scalability in mind.

Feedback on errors/issues is appreciated via github's functions.

FAILS is licensed via GNU Affero GPL version 3.0 

## Package ltihandler
This package contains the node server code to handle the requests through LTI.

## Installation
For installation instructions for a containerized envoironment, please see the [fails-components/compositions](https://github.com/fails-components/compositions "fails-components/compositions") repository.