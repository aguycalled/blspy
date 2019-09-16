from blspy import (PrivateKey, PublicKey, InsecureSignature, Signature,
                   PrependSignature, AggregationInfo, ExtendedPrivateKey,
                   Threshold, Util)
import random, hashlib

N = 4

class Wallet:
    wallet = {}

    def CreateKey(self):
        sk = PrivateKey.from_seed(bytes((random.getrandbits(8) for i in range(256))))
        pk = PublicKey(sk.get_public_key())
        self.wallet[pk.hash()] = sk

        return pk

    def GetPrivateKey(self, pk):
        if pk.hash() not in self.wallet:
            raise Exception('Unknown public key!')

        return self.wallet.get(pk.hash())

class PublicKey:
    def __init__(self, pk):
        self.pk = pk

    def hash(self):
        m = hashlib.sha256()
        m.update(self.pk.serialize())

        return m.digest()

    def serialize(self):
        return self.pk.serialize()

class Input:
    def __init__(self, output):
        self.prevout = output
        pk = wallet.GetPrivateKey(self.prevout.spendingkey)
        msg = self.hash()
        self.signature = pk.sign(msg)

    def hash(self):
        m = hashlib.sha256()
        m.update(self.prevout.hash())

        return m.digest()

    def verify(self):
        msg = self.hash()
        sig = self.signature
        sig.set_aggregation_info(AggregationInfo.from_msg(self.prevout.spendingkey.pk, msg))

        return sig.verify()

    def __str__(self):
        return "\tPrevout:\n{0}".format(str(self.prevout))

class Output:
    def __init__(self, bk, sk, value):
        self.blindingkey = bk
        self.spendingkey = sk
        self.value = pybullet.prove([value,1], N)
        pk = wallet.GetPrivateKey(bk)
        msg = self.hash()
        self.signature = pk.sign(msg)

    def hash(self):
        m = hashlib.sha256()
        m.update(self.blindingkey.serialize())
        m.update(self.spendingkey.serialize())

        return m.digest()

    def verify(self):
        msg = self.hash()
        sig = self.signature
        sig.set_aggregation_info(AggregationInfo.from_msg(self.blindingkey.pk, msg))

        return sig.verify()

    def __str__(self):
        return "\tBlindingKey: {0}\n\tSpendingKey: {1}\n\tValue: {2}\n".format(str(self.blindingkey.serialize().hex()), str(self.spendingkey.serialize().hex()), str(self.value))

class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

        sigs = []

        for input in self.inputs:
            sigs.append(input.signature)

        for output in self.outputs:
            sigs.append(output.signature)

        self.signature = Signature.aggregate(sigs)

    def hash(self):
        m = hashlib.sha256()
        m.update(self.inputs)
        m.update(self.outputs)
        return m.digest()

    def verify(self):
        aggregation_infos = []
        sig = self.signature

        in_value = 0

        for input in self.inputs:
            if input.verify() == False:
                return false
            aggregation_infos.append(AggregationInfo.from_msg(input.prevout.spendingkey.pk, input.hash()))
            in_value = in_value + input.prevout.value

        out_value = 0

        for output in self.outputs:
            if output.verify() == False:
                return false
            aggregation_infos.append(AggregationInfo.from_msg(output.blindingkey.pk, output.hash()))
            out_value = out_value + output.value

        sig.set_aggregation_info(AggregationInfo.merge_infos(aggregation_infos))

        return sig.verify() and in_value >= out_value

    def combine(self, tx):
        self.inputs = self.inputs + tx.inputs
        self.outputs = self.outputs + tx.outputs

        self.signature = Signature.aggregate([self.signature, tx.signature])

    def __str__(self):
        return "Inputs:\n{0}\nOutputs:\n{1}\nSignature: {2}".format('\n\n'.join([str(x) for x in self.inputs]), '\n\n'.join([str(x) for x in self.outputs]), str(self.signature.serialize().hex()))

wallet = Wallet()

genesis_output = Output(wallet.CreateKey(), wallet.CreateKey(), 10)

input1 = Input(genesis_output)
output1 = Output(wallet.CreateKey(), wallet.CreateKey(), 2)
output2 = Output(wallet.CreateKey(), wallet.CreateKey(), 8)

assert(input1.verify())
assert(output1.verify())
assert(output2.verify())

tx1 = Transaction([input1], [output1, output2])

assert(tx1.verify())

input2 = Input(output2)
output3 = Output(wallet.CreateKey(), wallet.CreateKey(), 8)

assert(input2.verify())
assert(output3.verify())

tx2 = Transaction([input2], [output3])

assert(tx2.verify())

tx1.combine(tx2)
assert(tx1.verify())
