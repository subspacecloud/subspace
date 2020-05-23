# Contributing

Welcome! If you're looking to help, this document is a great place to start!

## Building the project

To build Subspace from source, you will need [Go 1.13](https://golang.org/dl/) or later installed.

```sh
git clone git@github.com:subspacecommunity/subspace && cd subspace
make

# run
./subspace
```

## Git workflow

```sh
username=$your username
# add your remote/upstream
git remote add $username git@github.com:$username/subspace.git

# update from origin/master
git pull --rebase

# create a branch
git checkout -b my_feature

# push changes from my_feature to your fork.
#    -u, --set-upstream    set upstream for git pull/status
git push -u $username
```

## Go Resources

A few helpful resources for getting started with Go:

- [Writing, building, installing, and testing Go code](https://www.youtube.com/watch?v=XCsL89YtqCs)
- [Resources for new Go programmers](http://dave.cheney.net/resources-for-new-go-programmers)
- [How I start](https://howistart.org/posts/go/1)
- [How to write Go code](https://golang.org/doc/code.html)
