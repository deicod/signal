package senderkeys

import "testing"

func FuzzDeserializeRecordDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("SIGK"))

	seed := make([]byte, 0, recordMinSize+128)
	seed = append(seed, []byte("SIGK")...)
	seed = append(seed, recordSerializeVersion)
	seed = append(seed, 0, 1) // maxStates = 1
	seed = append(seed, 0, 1) // stateCount = 1

	seed = append(seed, senderKeyMessageVersion)
	seed = append(seed, make([]byte, distributionIDSize)...)
	seed = append(seed, 0, 0, 0, 1)                         // keyID
	seed = append(seed, 0, 0, 0, 0)                         // chainIteration
	seed = append(seed, make([]byte, senderKeySeedSize)...) // chainSeed
	seed = append(seed, make([]byte, 32)...)                // signingPublic
	seed = append(seed, 0)                                  // hasPrivate = false
	seed = append(seed, 0, 0)                               // messageKeyCount

	f.Add(seed)

	seedV1 := make([]byte, 0, recordMinSize+128)
	seedV1 = append(seedV1, []byte("SIGK")...)
	seedV1 = append(seedV1, 1)
	seedV1 = append(seedV1, 0, 1)                               // maxStates = 1
	seedV1 = append(seedV1, 0, 1)                               // stateCount = 1
	seedV1 = append(seedV1, 0, 0, 0, 1)                         // keyID
	seedV1 = append(seedV1, 0, 0, 0, 0)                         // chainIteration
	seedV1 = append(seedV1, make([]byte, senderKeySeedSize)...) // chainSeed
	seedV1 = append(seedV1, make([]byte, 32)...)                // signingPublic
	seedV1 = append(seedV1, 0)                                  // hasPrivate = false
	seedV1 = append(seedV1, 0, 0)                               // messageKeyCount
	f.Add(seedV1)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeRecord(data)
	})
}

func FuzzParseDistributionMessageDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})

	var distID [distributionIDSize]byte
	seed := distributionMessage{
		messageVersion: senderKeyMessageVersion,
		distributionID: distID,
		keyID:          1,
		iteration:      0,
	}.serialize()
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDistributionMessage(data)
	})
}

func FuzzParseSenderKeyMessageDoesNotPanic(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})

	var distID [distributionIDSize]byte
	seed := senderKeyMessage{
		messageVersion: senderKeyMessageVersion,
		distributionID: distID,
		keyID:          1,
		iteration:      0,
	}.serialize()
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseSenderKeyMessage(data)
	})
}
