package deletion

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteOneRejectsUnrecognisedMethod pins the fail-closed branch in
// deleteOne. Before it existed, every method that was not exactly MethodTrash
// fell through to DeleteMessage, so a manifest carrying an unfamiliar method --
// hand-edited, or written by a binary that knows an operation this one does not
// -- would permanently destroy mail instead of being refused.
func TestDeleteOneRejectsUnrecognisedMethod(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tc := NewTestContext(t)

	result, err := tc.Exec.deleteOne(context.Background(), 1, "msg-1", Method("archive"))

	require.Error(err)
	assert.Equal(resultFatal, result, "an unknown method must halt execution")
	assert.Contains(err.Error(), "archive")
	assert.Empty(tc.MockAPI.DeleteCalls, "no message may be permanently deleted")
	assert.Empty(tc.MockAPI.TrashCalls, "no message may be trashed")
}

// TestDeleteOneAcceptsKnownMethods keeps the guard honest: the two real methods
// must still reach their respective provider calls.
func TestDeleteOneAcceptsKnownMethods(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tc := NewTestContext(t)
	ctx := context.Background()

	result, err := tc.Exec.deleteOne(ctx, 1, "msg-trash", MethodTrash)
	require.NoError(err)
	assert.Equal(resultSuccess, result)

	result, err = tc.Exec.deleteOne(ctx, 1, "msg-delete", MethodDelete)
	require.NoError(err)
	assert.Equal(resultSuccess, result)

	assert.Equal([]string{"msg-trash"}, tc.MockAPI.TrashCalls)
	assert.Equal([]string{"msg-delete"}, tc.MockAPI.DeleteCalls)
}
