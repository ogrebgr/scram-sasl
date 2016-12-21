# SCRAM SASL authentication for Java
Java library that implements SCRAM SASL ([RFC5802](https://tools.ietf.org/html/rfc5802)) for both server and client.

Includes SHA-1, SHA-256, SHA-512 implementations and examples (you can easily create implementation that uses your own hashing function and digest).

This library was created because there was no Java-friendly implementation for client or server. Existing implementations were looking like a port of C/C++ code and/or was using [Oracle's SASL API](https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html) which is a) way too abstract for the 99% of the projects and b) not available on all platforms (Android, OpenJDK). Current library intentionally uses simple and straightforward approach in order to provide easy integration.


# Why use SCRAM?
Please go to this [Wikipedia page](https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism) for a good explanation why it is good idea to use SCRAM.

In short: SCRAM provides more security in (at least) two aspects:

1. You don't keep the passwords in your database weakly hashed (MD5/SHA-1) and thus even if your database is stolen the attacker cannot guess the passwords;
2. During the authentication passwords are never send in clear form thus eliminating the use of man-in-the-middle attack.


# How to use the library
There are two ways to use the library:
* High level usage - which is described bellow and provides classes that can be used as a base for your client or server (`Scram*SaslClientProcessor`, `Scram*SaslServerProcessor`)
* Low level usage - you can use directly/manually the building blocks in order to create your own implementation of server/client (`ScramClientFunctionalityImpl`, `ScramServerFunctionalityImpl`).

## Server

To support SCRAM your server will need two distinct functionalities: user registration and user authentication.

Bellow are the simplified explanations (for detailed ones please read the [standard](https://tools.ietf.org/html/rfc5802)).

User registration goes like this:
1. An user fills in registration form
2. The user sends the data which contains username and password along with potential other fields
3. The server generates `salt`, `serverKey`, `storedKey` and `iterations` and stores them along with the username locally usually in DB. Please note that the password is not stored in clear or hashed form.

User authentication goes like this:
1. Client sends the *first message* which contains the username
2. Server loads the user data for that username which contain the `salt`, `serverKey`, `storedKey` and `iterations` and sends back the `salt` and the `iterations` value (*server's first message*).
3. Client uses the `salt` and the `iterations` to 'salt' his password and compute a `proof` which he sends back to the server (*client's final message*)
4. Server uses the `serverKey` and the `storedKey` to analyze the `proof` and determine if it is correct and sends to the client its *final message*.



### User registration

For the user registration you will need the static method `ScramUtils.newPassword()`:

```Java
// given we have username and password in clear text received from the user
String username = ...
String password = ...

// ... we generate salt
SecureRandom random = new SecureRandom();
byte[] salt = new byte[24];
random.nextBytes(salt);

// ... then we generate value for the 'iterations' between 4096 and 6000
int iterations = 4096 + random.nextInt(1092);

// Compute user data using SHA-256
NewPasswordByteArrayData userDataArr = ScramUtils.newPassword(password,
                                                              salt,
                                                              iterations,
                                                              "HmacSHA256",
                                                              "SHA-256"
                                                              );

// transform the data into DB friendly format i.e. String
NewPasswordStringData userDataString = ScramUtils.byteArrayToStringData(userDataArr);

// save the user data in your DB using `username` as key
...
```

### Authentication (login)
For your server you will need some of the `ScramSha*SaslServerProcessor` classes in order to process the authentication sequence. You will have to create a new instance per each authentication.

There are 4 parameters needed to create an instance:
* `long connectionId` - usually a server tracks its clients by connection ID which is assigned upon connection. Use this ID as first parameter. If your server uses something different than a `long` you will need to modify the lib (initially it was created to use generic parameter for `connectionId` but later I've decided that it is an overkill which only complicates the implementation).
* [Listener](https://github.com/ogrebgr/scram-sasl/blob/master/lib/src/main/java/com/bolyartech/scram_sasl/server/ScramSaslServerProcessor.java#L118) `listener` - you will have to provide implementation of `ScramSaslServerProcessor.Listener`. It has `void onSuccess(long connectionId);` and `void onFailure(long connectionId);` methods which will be used to notify your code that authentication has completed.
* [UserDataLoader](https://github.com/ogrebgr/scram-sasl/blob/master/lib/src/main/java/com/bolyartech/scram_sasl/server/ScramSaslServerProcessor.java#L105) `userDataLoader` - you will have to provide implementation that loads the user data from the DB and calls back the processor's `onUserDataLoaded()`.
* [Sender](https://github.com/ogrebgr/scram-sasl/blob/master/lib/src/main/java/com/bolyartech/scram_sasl/server/ScramSaslServerProcessor.java#L135) `sender` - you will have to provide implementation that sends messages to the clients

```Java
// usually you will have global listener, user loader and sender
mListener = new Listener() {...}
mLoader = new UserDataLoader() {...}
mSender = new Sender() {...}
```

When a client connects:
```Java
// you will have connection ID
long connectionId = ...
ScramSaslServerProcessor processor = new ScramSha256SaslServerProcessor(
                                                      connectionId,
                                                      listener,
                                                      loader,
                                                      sender
);

// usually you will have a map where processors are kept
mScramProcessors.put(connectionId, processor);
```

When you receive message:
```Java
void onMessageReceived(long connectionId, String message) {
    // first you get the needed processor
    ScramSaslServerProcessor processor = mScramProcessors.get(connectionId);

    // then you feed in the message
    processor.onMessage(message);

    // from this point on everything is automatic and you just wait for onSuccess
    // or onFailure call or abort the procedure with abort() (if for example it takes too long)
}
```

After creating the instance you just wait for the *first client message* and feed it to the processor via `onMessage(String message)`. The processor will extract the username from it and call your implementation of UserDataLoader's `loadUserData(String username, long connectionId, ScramSaslServerProcessor processor)`. There you will initiate the loading of the data (by adding the request to some queue for example) and when the data is available you will call processor's `onUserDataLoaded(UserData data)` which will prepare the `first server message` and send it to the client using your `Sender` implementation.

On the other side client will prepare it's *final message* and send it back to your server. When you receive it you will feed it again to `onMessage(String message)` and processor will prepare the `server final message` and send it. After that your listener will be called with `onSuccess` or `onFailure` depending on the success of the authentication. Please note that `onFailure` might be called at any stage of the authentication procedure if there is a problem with the authentication.

You must take care on your own to interrupt the sequence with `abort()` after given timeout if there is no outcome.


For an example please see the [SCRAM SHA-256 SASL example](https://github.com/ogrebgr/scram-sasl/blob/master/examples/src/main/java/com/bolyartech/scram_sasl/examples/ScramSha256Example.java).


## Client

To authenticate as a client you will need an instance of some of the `ScramSha*SaslClientProcessor` classes.

There are two parameters needed to create an instance:
* [Listener](https://github.com/ogrebgr/scram-sasl/blob/master/lib/src/main/java/com/bolyartech/scram_sasl/client/ScramSaslClientProcessor.java#L52) `listener` - will be used to notify your code of the authentication outcome. Implementation of `ScramSaslClientProcessor.Listener`;
* [Sender](https://github.com/ogrebgr/scram-sasl/blob/master/lib/src/main/java/com/bolyartech/scram_sasl/client/ScramSaslClientProcessor.java#L68) `sender` - will be used to send messages to the server. Implementation of `ScramSaslClientProcessor.Sender`

After creating the instance you have to initiate the sequence by calling the `start()` method of the processor:

```Java
// get the username and password from the UI
String username = ...
String password = ...

Listener listener = new Listener() {...};
Sender sender = new Sender() {...};

ScramSaslClientProcessor processor = new ScramSha256SaslClientProcessor(
                                          listener, sender);

processor.start(username, password);                                          
```
When you call `start()` `first client message` will be prepared and send to the server.

Now we are waiting for server to reply. When you receive message from the server you have to feed it to the processor:

```Java
// message is received
String message = ...
processor.onMessage(message);
```
From that point on everything goes automatically. When the sequence is completed your listener will be notified with `onSuccess` or `onFailure` depending on the success of the authentication. Please note that `onFailure` might be called at any stage of the authentication procedure if there is a problem with the authentication.

You must take care on your own to interrupt the sequence with `abort()` after given timeout if there is no outcome.

# Download

Gradle

`compile 'com.bolyartech.scram_sasl:scram_sasl:1.0.1'`


# Credits
Server implementation is based on [ScramSha1SaslServer](http://download.igniterealtime.org/openfire/docs/4.0.2/documentation/javadoc/org/jivesoftware/openfire/sasl/ScramSha1SaslServer.html) created by Richard Midwinter for the
[OpenFire XMPP Server](https://www.igniterealtime.org/projects/openfire/)

Client implementatin is based on AbstractScramSaslClient from [Qpid JMS](https://qpid.apache.org/components/jms/) project.

StringPrep and Normalizer are using code created by Glenn Maynard with some minor modifications in order to suppress typo warnings in Intellij IDEA.


# License
Copyright 2016 Ognyan Bankov

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
