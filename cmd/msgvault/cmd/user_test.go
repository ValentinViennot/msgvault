package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSourceIDs(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	ids, err := parseSourceIDs(" 3, 1 ,2 ")
	require.NoError(err)
	assert.Equal([]int64{3, 1, 2}, ids)
	ids, err = parseSourceIDs("none")
	require.NoError(err)
	assert.Empty(ids)
	assert.NotNil(ids, "none binds an empty set, not a missing one")
	_, err = parseSourceIDs("1,x")
	require.Error(err)
	_, err = parseSourceIDs("0")
	require.Error(err)
	assert.Equal("none", formatSourceIDs(nil))
	assert.Equal("1,3", formatSourceIDs([]int64{1, 3}))
}
