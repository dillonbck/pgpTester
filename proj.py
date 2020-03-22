#!/usr/bin/python3

from names_list import NAMES_LIST
import random
from graphviz import Digraph
import copy


takenNames = [-1]


TRUST_NONE = 0
TRUST_PARTIAL = 1
TRUST_FULL = 2
TRUST_ULTIMATE = 3
TRUST_LEVEL_STRINGS = {TRUST_NONE: "None",
                       TRUST_PARTIAL: "Partial",
                       TRUST_FULL: "Full",
                       TRUST_ULTIMATE: "Ultimate"}
trustLevelProbability = {TRUST_NONE: 1, #only matters is signed keys partial trust
                         TRUST_PARTIAL: .1,
                         TRUST_FULL: .01,
                         TRUST_ULTIMATE: 0}

def getRandomName():
    x = -1
    while x in takenNames:
        x = random.randint(0,len(NAMES_LIST)-1)
    name = NAMES_LIST[x]
    takenNames.append(x)
    if len(takenNames)-1 == len(NAMES_LIST):
        raise ValueError("All names exhausted")
    return name

class User(object):
    def __init__(self, trustLevel=None, name=None):
        if not trustLevel:
            self.trustLevel = TRUST_NONE
        else:
            self.trustLevel = trustLevel
        self._initialTrustLevel = self.trustLevel

        # Other users that this user has signed
        self.signees = []

        # Other users that have signed this user
        self.signers = []


        if not name:
            self.name = getRandomName()
        else:
            self.name = name

        self.badActor = False
        self.valid = False

        self.pathLengthToMainUser = -1

    def resetToInitialWebState(self):
        self.resetTrustLevel()
        self.resetValidation()
        self.resetPathLengthToMaster()

    def resetTrustLevel(self):
        self.trustLevel = self._initialTrustLevel

    def resetValidation(self):
        self.valid = False

    def resetPathLengthToMaster(self):
        self.pathLengthToMainUser = -1

    def addSigner(self, signer):
        self.signers.append(signer)

    def addSignee(self, signee):
        self.signees.append(signee)

    @property
    def identifier(self):
        out = (self.name + "\n" +
               TRUST_LEVEL_STRINGS[self.trustLevel] + "\n" +
               str(self.pathLengthToMainUser))
        return out

    def __eq__(self, other):
        if self.name == other.name:
            return True
        return False

def main():

    for x in range(1):
        run_test()

def run_test():
    numMainSignedUsersList = [50]
    numOtherUsersList = [100]
    probImmediateFullTrustList = [1]
    probBadActorList = [.2]
    probOtherSignedList = [3]

    #numMainSignedUsersList = [5, 10, 20, 100, 200] # number of users signed by main user
    #probImmediateFullTrustList = [1] # probability that mainSignedUsers user has partial or full trust
    #numOtherUsersList = [10, 20, 40, 200, 400] # number of otherUser users
    #probBadActorList = [.2, .5, .8] # probability that otherUser user is a bad actor
    #probOtherSignedList = [2, 3, 4] # probability that mainSignedUser+otherUsers user will sign an otherUser # density of the web: sparse, normal, dense

    for numMainSignedUsers in numMainSignedUsersList:
        for probImmediateFullTrust in probImmediateFullTrustList:
            for numOtherUsers in numOtherUsersList:
                for probBadActor in probBadActorList:
                    for probOtherSigned in probOtherSignedList:

                        mainUser, mainSignedUsers, otherUsers = createWebOfUsers(numMainSignedUsers,
                                                                                 numOtherUsers,
                                                                                 probImmediateFullTrust,
                                                                                 probBadActor,
                                                                                 probOtherSigned)

                        #makeAllValidKeysPartialTrustList = [True, False]
                        #numMarginallyTrustedRequiredList = [1,2,3,4]
                        #maxPathLengthList = [2,3,4,5]
                        makeAllValidKeysPartialTrustList = [False]
                        numMarginallyTrustedRequiredList = [1,2,3]
                        maxPathLengthList = [3]

                        count = 0
                        for makeAllValidKeysPartialTrust in makeAllValidKeysPartialTrustList:
                            for numMarginallyTrustedRequired in numMarginallyTrustedRequiredList:
                                for maxPathLength in maxPathLengthList:
                                    count += 1

                                    # Since we're retesting the same web of users again, reset
                                    # them so that they dont have any valid/trust/distance to main
                                    # information that would pollute the next validation configuration
                                    for user in [mainUser] + mainSignedUsers + otherUsers:
                                        user.resetToInitialWebState()

                                    validateKeys(mainUser, mainSignedUsers,
                                                otherUsers, numMarginallyTrustedRequired,
                                                makeAllValidKeysPartialTrust, maxPathLength)

                                    print("Web Configuration: ")
                                    print("numMainSignedUsers:", numMainSignedUsers)
                                    print("probImmediateFullTrust:", probImmediateFullTrust)
                                    print("numOtherUsers:", numOtherUsers)
                                    print("probBadActor:", probBadActor)
                                    print("probOtherSigned:", probOtherSigned)

                                    print("Validation Configuration: ")
                                    print("makeAllValidKeysPartialTrust:", makeAllValidKeysPartialTrust)
                                    print("numMarginallyTrustedRequired:", numMarginallyTrustedRequired)
                                    print("maxPathLength:", maxPathLength)

                                    report = generateReport(mainUser, mainSignedUsers, otherUsers)
                                    printReport(report)

                                    print("")

                                    # Build graph of web of users
                                    g = Digraph('G', filename='hello.gv' + str(count))
                                    buildGraph(g, mainUser, mainSignedUsers, otherUsers)
                                    g.view()
                                    #import pdb
                                    #pdb.set_trace()


def createWebOfUsers(numMainSignedUsers, numOtherUsers,
                     probImmediateFullTrust, probBadActor,
                     probOtherSigned):
    # Reset taken names, we're creating a new web
    global takenNames
    takenNames = [-1]

    mainUser = User(TRUST_ULTIMATE)

    # Create partially completed web of users
    mainSignedUsers, otherUsers = createUsers(mainUser, numMainSignedUsers,
                                              numOtherUsers, probImmediateFullTrust)

    # Some "other" users are bad actors
    assignBadActors(otherUsers, probBadActor)

    # Have other users get signed based on probability
    signOtherUsersConsideringBadActors(mainSignedUsers, otherUsers, probOtherSigned)

    return mainUser, mainSignedUsers, otherUsers

def createUsers(mainUser, numMainSignedUsers, numOtherUsers,
                     probImmediateFullTrust):
    # Generate a set of users signed by main user
    mainSignedUsers = createMainSignedUsers(mainUser, numMainSignedUsers, probImmediateFullTrust)

    # Generate a set of users NOT signed by main user
    # They might be signed by other users
    otherUsers = createOtherUsers(numOtherUsers)

    return mainSignedUsers, otherUsers

def createMainSignedUsers(mainUser, numMainSignedUsers, probImmediateFullTrust):
    mainSignedUsers = []
    for _ in range(numMainSignedUsers):
        if random.random() < probImmediateFullTrust: # randomly choose whether full or partial trust
            trustLevel = TRUST_FULL
        else:
            trustLevel = TRUST_PARTIAL
        user = User(trustLevel)
        user.addSigner(mainUser)# immediate users signed by mainSignedUser
        mainUser.addSignee(user)
        mainSignedUsers.append(user)

    return mainSignedUsers

def createOtherUsers(numOtherUsers):
    otherUsers = []
    for _ in range(numOtherUsers):
        user = User(TRUST_NONE) # initially do not trust other users at all
                                # might change if their key is validated
        otherUsers.append(user)

    return otherUsers

def assignBadActors(otherUsers, probBadActor):
    for user in otherUsers:
        x = random.random()
        if x < probBadActor:
            user.badActor = True

def signOtherUsersConsideringBadActors(mainSignedUsers, otherUsers, probOtherSigned):
    for user in otherUsers:
        for signer in mainSignedUsers + otherUsers:
            if user == signer:
                continue

            # Random probability that signer even considers signing user's key
            n = random.normalvariate(probOtherSigned, .1)
            n /= len(mainSignedUsers + otherUsers)

            x = random.random()
            if x < n:
                # Signer is considering whether or not to sign user's key
                if not user.badActor:
                    # User is not a bad actor, so they get signed
                    user.addSigner(signer)
                    signer.addSignee(user)
                else:
                    # User is a bad actor, lets see if the signer incorrectly signs
                    y = random.random()
                    if y < trustLevelProbability[signer.trustLevel]:
                        if signer.trustLevel != TRUST_NONE:
                            print("Incorrectly signed bad actor: ", user.name)
                            print(y, "<", trustLevelProbability[signer.trustLevel])
                        # Signer incorrectly identified signed the key of a bad actor
                        user.addSigner(signer)
                        signer.addSignee(user)

def validateKeys(mainUser, mainSignedUsers, otherUsers, numMarginallyTrustedRequired,
                 makeAllValidKeysPartialTrust, maxPathLength):
    # Run key validation calculations
    count = 0
    recheckValidKeys = True
    while recheckValidKeys:
        count += 1
        recheckValidKeys = calculateValidKeys(mainUser, mainSignedUsers,
                                              otherUsers, numMarginallyTrustedRequired,
                                              makeAllValidKeysPartialTrust)

    # After keys have been validated, generate distance for each user to main user
    calculatePathLengthToMainUser(mainUser)

    # Mark keys too far away as invalid based on maxPathLength
    invalidateKeysTooFarAway(otherUsers, maxPathLength)

    ## Calculate bad actors
    #calculateBadActors(mainUser, mainSignedUsers, otherUsers)

    ## Print web of users
    #printAllUsers(mainUser, mainSignedUsers, otherUsers)

def calculateValidKeys(mainUser, mainSignedUsers, otherUsers, numMarginallyTrustedRequired,
                       makeAllValidKeysPartialTrust):
    mainUser.valid = True # automatically validate own key
    for user in mainSignedUsers:
        user.valid = True # valid if signed by yourself

    #recheckValidKeys = True
    #while recheckValidKeys:
    recheckValidKeys = False
    for user in otherUsers:
        if user.valid:
            # This user has already been validated
            continue
        fullyTrustedSigner = False
        numMarginallyTrustedSigners = 0
        for signingUser in user.signers:
            if signingUser.trustLevel == TRUST_PARTIAL:
                if signingUser.valid:
                    numMarginallyTrustedSigners += 1
                    if numMarginallyTrustedSigners == numMarginallyTrustedRequired:
                        break
                else:
                    print("invalid signer can't count")
            elif signingUser.trustLevel == TRUST_FULL:
                fullyTrustedSigner = True
                break
        if fullyTrustedSigner or numMarginallyTrustedSigners == numMarginallyTrustedRequired:
            user.valid = True
            recheckValidKeys = True
            if makeAllValidKeysPartialTrust:
                user.trustLevel = TRUST_PARTIAL # OPTION: make all valid keys partial trust
    return recheckValidKeys

def calculateBadActors(mainUser, mainSignedUsers, otherUsers):
    for user in [mainUser] + mainSignedUsers + otherUsers:
        if mainUser in user.signers:
            pass

        else:
            probability_bad = -1
            for signingUser in user.signers:
                if signingUser.trustLevel != None:
                    if probability_bad == -1:
                        probability_bad = trustLevelProbability[signingUser.trustLevel]
                    else:
                        probability_bad *= trustLevelProbability[signingUser.trustLevel]

            if probability_bad != -1:
                x = random.random()
                if x < probability_bad:
                    user.badActor = True
                user.probabilityBad = probability_bad


def buildGraph(g, mainUser, mainSignedUsers, otherUsers):
    #print("Main User: ", mainUser.name)
    g.attr('node', shape='doublecircle')
    g.node(mainUser.identifier)

    g.attr('node', shape='circle')
    for user in mainSignedUsers:
        style = ''
        fillcolor = 'white'
        shape = 'circle'
        if user.badActor:
            style = 'filled'
            fillcolor = 'red'
        if not user.valid:
            shape = 'box'
        g.node(user.identifier, style=style, fillcolor=fillcolor, shape=shape)
        #print(user.badActor)
        for signedUser in user.signers:
            g.edge(signedUser.identifier, user.identifier, label='')

    for user in otherUsers:
        #print(user.badActor)
        style = ''
        fillcolor = 'white'
        shape = 'circle'
        if user.badActor:
            style = 'filled'
            fillcolor = 'red'
        if not user.valid:
            shape = 'box'
        g.node(user.identifier, style=style, fillcolor=fillcolor, shape=shape)
        for signedUser in user.signers:
            g.edge(signedUser.identifier, user.identifier, label='')



    #f.attr('node', shape='doublecircle')
    #f.node('LR_0')

    #f.attr('node', shape='circle')
    #f.edge('LR_0', 'LR_2', label='SS(B)')

def calculatePathLengthToMainUser(mainUser):
    mainUser.pathLengthToMainUser = 0
    user = mainUser
    calcPathLength(user)

def calcPathLength(user):
    for signee in user.signees:
        if signee.pathLengthToMainUser == -1:
            signee.pathLengthToMainUser = user.pathLengthToMainUser + 1
            calcPathLength(signee)
        elif signee.pathLengthToMainUser > user.pathLengthToMainUser + 1:
            signee.pathLengthToMainUser = user.pathLengthToMainUser + 1
            calcPathLength(signee)


def invalidateKeysTooFarAway(otherUsers, maxPathLength):
    for user in otherUsers:
        if user.valid:
            if user.pathLengthToMainUser > maxPathLength:
                user.valid = False

class Report(object):
    def __init__(self, mainUser, mainSignedUsers, otherUsers):
        self.mainUser = mainUser
        self.mainSignedUsers = mainSignedUsers
        self.otherUsers = otherUsers

    @property
    def numBadActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if user.badActor:
                count += 1
        return count

    @property
    def numValidBadActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if user.badActor and user.valid:
                count += 1
        return count

    @property
    def numInvalidBadActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if user.badActor and not user.valid:
                count += 1
        return count

    @property
    def numGoodActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if not user.badActor:
                count += 1
        return count

    @property
    def numValidGoodActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if not user.badActor and user.valid:
                count += 1
        return count

    @property
    def numInvalidGoodActors(self):
        count = 0
        for user in self.mainSignedUsers + self.otherUsers:
            if not user.badActor and not user.valid:
                count += 1
        return count


def generateReport(mainUser, mainSignedUsers, otherUsers):
    report = Report(mainUser, mainSignedUsers, otherUsers)
    return report

def printReport(report):
    print("Test Report")
    print("Number of Valid Bad Actors: ", report.numValidBadActors)
    if report.numBadActors != 0:
        print("Percentage Bad Actors Invalid: ", (report.numInvalidBadActors/report.numBadActors)*100)
    else:
        print("Percentage Bad Actors Invalid: 100%")
    print("Number of Invalid Good Actors: ", report.numInvalidGoodActors)
    print("Percentage Good Actors Validated: ", (report.numValidGoodActors/report.numGoodActors)*100)


def printAllUsers(mainUser, mainSignedUsers, otherUsers):
    print("Main User: ", mainUser.name)
    print("-------------")

    for user in mainSignedUsers:
        print("mainSignedUser: ", user.name)
        print(user.badActor)
        print(user.valid)
        print("signed by: ")
        for signedUser in user.signers:
            print(signedUser.name)
        print("")
    print("-------------")

    for user in otherUsers:
        print("user: ", user.name)
        print(user.badActor)
        print(user.valid)
        print("signed by: ")
        for signedUser in user.signers:
            print(signedUser.name)
        print("")



if __name__ == "__main__":
    main()

