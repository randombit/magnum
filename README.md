# Magnum

magnum is a tool for distributing afl-fuzz over EC2 spot nodes

![Magnum](magnum.jpg)

Multiple fuzzing jobs can be created, each with a maximum cost per hour.
magnum creates EC2 spot instances which fuzz the target, respawning new
fuzzballs as spot instances are terminated.

NOTE WELL: This is alpha software and has no warranty. It might kick
you in the shin and/or run up a big bill on spot instances in Singapore.
Read LICENSE for the full disclaimer.

Basic usage. Start the server with

$ magum server --server=1.2.3.4 --db=~/magnum.db

The filename can point anywhere as it is a sqlite database

default port is #####

The server must be publically accessible from EC2. It's easiest to run it
on an EC2 node (not a spot node!)

Right now adding a job must be done on the server host:

$ magnum job add "Libfoo" foo_afl_binary corpus_dir
Job job_Q62F6OFgqjEqXRhR created
$ magnum --server=1.2.3.4 job list
job_Q62F6OFgqjEqXRhR "Libfoo" 0 workers 0 execs

# later on...

$ magnum --server=1.2.3.4 job list
job_Q62F6OFgqjEqXRhR "Libfoo" 4 workers 1040000 execs

$ magnum --server=1.2.3.4 job info job_Q62F6OFgqjEqXRhR
res_### crash <blobId1> found YYYYMMDDHHMM
res_### hang <blobId2> found YYYYMMDDHHMM

$ magnum --server=1.2.3.4 get <blobId1>
# writes to file named <blobId> by default, or else --output

$ magnum --server=1.2.3.4 job stop job_Q62F6OFgqjEqXRhR
Job job_Q62F6OFgqjEqXRhR stopped

