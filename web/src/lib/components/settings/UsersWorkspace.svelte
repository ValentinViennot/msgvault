<script lang="ts">
  import {
    listSourceStatus as generatedListSourceStatus,
    listUsers as generatedListUsers,
    patchUser as generatedPatchUser,
    setUserSources as generatedSetUserSources,
  } from '../../api/generated/api/api';
  import { Button, Checkbox } from '@kenn-io/kit-ui';
  import { onMount } from 'svelte';
  import type { APIClient } from '../../api/client';
  import type { SourceStatus, UserSummary } from '../../api/generated/models';

  let { client }: { client: APIClient } = $props();

  let users = $state<UserSummary[]>([]);
  let sources = $state<SourceStatus[]>([]);
  let loading = $state(true);
  let busyUser = $state<number | undefined>();
  let error = $state('');

  function messageFor(problem: unknown, fallback: string): string {
    if (typeof problem === 'object' && problem !== null && 'message' in problem) {
      const message = (problem as { message?: unknown }).message;
      if (typeof message === 'string' && message) return message;
    }
    return fallback;
  }

  function sourceLabel(source: SourceStatus): string {
    return source.display_name ? `${source.display_name} (${source.identifier})` : source.identifier;
  }

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      const [userResult, sourceResult] = await Promise.all([
        generatedListUsers(client),
        generatedListSourceStatus(undefined, client),
      ]);
      if (!userResult.data) throw new Error(messageFor(userResult.error, 'Unable to load users.'));
      if (!sourceResult.data) throw new Error(messageFor(sourceResult.error, 'Unable to load sources.'));
      users = userResult.data.users;
      sources = sourceResult.data.sources ?? [];
    } catch (problem) {
      error = messageFor(problem, 'Unable to load users.');
    } finally {
      loading = false;
    }
  }

  function replace(updated: UserSummary): void {
    users = users.map((user) => (user.id === updated.id ? updated : user));
  }

  async function setSource(user: UserSummary, sourceId: number, visible: boolean): Promise<void> {
    const next = visible
      ? [...user.source_ids.filter((id) => id !== sourceId), sourceId].sort((a, b) => a - b)
      : user.source_ids.filter((id) => id !== sourceId);
    busyUser = user.id;
    error = '';
    try {
      const { data, error: problem } = await generatedSetUserSources({ id: user.id }, { source_ids: next }, client);
      if (!data) throw new Error(messageFor(problem, 'Unable to update sources.'));
      replace(data);
    } catch (problem) {
      error = messageFor(problem, 'Unable to update sources.');
    } finally {
      busyUser = undefined;
    }
  }

  async function setDisabled(user: UserSummary, disabled: boolean): Promise<void> {
    busyUser = user.id;
    error = '';
    try {
      const { data, error: problem } = await generatedPatchUser({ id: user.id }, { disabled }, client);
      if (!data) throw new Error(messageFor(problem, 'Unable to update user.'));
      replace(data);
    } catch (problem) {
      error = messageFor(problem, 'Unable to update user.');
    } finally {
      busyUser = undefined;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<section class="users" aria-label="Users">
  <p class="intro">
    Administrators see every source. Everyone else sees only the sources ticked here; a user with no source
    sees no messages.
  </p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if loading}
    <p class="state" role="status">Loading users…</p>
  {:else if users.length === 0}
    <p class="state" role="status">No user has signed in yet.</p>
  {:else}
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th scope="col">User</th>
            <th scope="col">Role</th>
            <th scope="col">Standing</th>
            {#each sources as source (source.id)}
              <th scope="col">{sourceLabel(source)}</th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each users as user (user.id)}
            <tr class:disabled={user.disabled}>
              <th scope="row">
                <strong>{user.display_name || user.email}</strong>
                {#if user.display_name}<small>{user.email}</small>{/if}
              </th>
              <td>{user.role}</td>
              <td>
                <Button
                  tone="info"
                  surface="solid"
                  disabled={busyUser === user.id}
                  label={user.disabled ? 'Enable' : 'Disable'}
                  onclick={() => void setDisabled(user, !user.disabled)}
                />
              </td>
              {#each sources as source (source.id)}
                <td>
                  <Checkbox
                    checked={user.role === 'admin' || user.source_ids.includes(source.id)}
                    disabled={user.role === 'admin' || busyUser === user.id}
                    ariaLabel={`${user.email} sees ${sourceLabel(source)}`}
                    onchange={(checked) => void setSource(user, source.id, checked)}
                  />
                </td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .users {
    display: grid;
    gap: 1rem;
  }
  .intro,
  .state {
    margin: 0;
  }
  .error {
    color: var(--status-danger-ink, currentColor);
  }
  .table-scroll {
    overflow-x: auto;
  }
  table {
    border-collapse: collapse;
    min-width: 100%;
  }
  th,
  td {
    padding: 0.5rem 0.75rem;
    text-align: left;
    vertical-align: middle;
    border-bottom: 1px solid var(--border-subtle, currentColor);
  }
  th[scope='row'] {
    display: grid;
  }
  th[scope='row'] small {
    font-weight: normal;
    opacity: 0.75;
  }
  tr.disabled th[scope='row'] {
    opacity: 0.55;
  }
</style>
