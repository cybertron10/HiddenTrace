package paramsmapper

import "github.com/sergi/go-diff/diffmatchpatch"

func responseChanged(baselineResponses []ResponseData, new ResponseData, equalCheck bool) bool {
	for _, baseline := range baselineResponses {
		if equalCheck && responsesAreEqual(baseline, new) {
			return false
		} else if !equalCheck && responsesAreSimilar(baseline, new) {
			return false
		}
	}
	return true // Response is different from all baselines; significant change detected
}

func responsesAreSimilar(a, b ResponseData) bool {
	similarityThreshold := 0.9
	similarity := 1.0
	if len(a.Body) != len(b.Body) {
		similarity = computeSimilarity(a.Body, b.Body)
	}

	return a.StatusCode == b.StatusCode &&
		a.Reflections == b.Reflections &&
		similarity >= similarityThreshold
}

func responsesAreEqual(a, b ResponseData) bool {
	return a.StatusCode == b.StatusCode &&
		a.Reflections == b.Reflections &&
		len(a.Body) == len(b.Body)
}

func baselineResponsesAreConsistent(baselineResponses []ResponseData, compareFunc func(ResponseData, ResponseData) bool) bool {
	for i := 0; i < len(baselineResponses); i++ {
		for j := i + 1; j < len(baselineResponses); j++ {
			if !compareFunc(baselineResponses[i], baselineResponses[j]) {
				return false
			}
		}
	}
	return true
}

func computeSimilarity(aBody, bBody []byte) float64 {
	aText := string(aBody)
	bText := string(bBody)

	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(aText, bText, false)

	distance := dmp.DiffLevenshtein(diffs)

	// Calculate the maximum possible distance
	maxLen := len(aText)
	if len(bText) > maxLen {
		maxLen = len(bText)
	}

	if maxLen == 0 {
		return 1.0 // Both strings are empty, so they are identical
	}

	// Compute similarity as (1 - (distance / maxLen))
	similarity := 1 - float64(distance)/float64(maxLen)
	return similarity
}
