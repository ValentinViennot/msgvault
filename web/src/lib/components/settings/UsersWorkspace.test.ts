import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import { createSessionController } from '../../api/session.svelte';
import UsersWorkspace from './UsersWorkspace.svelte';

const users = [
  { id: 7, email: 'alice@example.com', display_name: 'Alice', role: 'member', disabled: false, source_ids: [1] },
  { id: 8, email: 'root@example.com', role: 'admin', disabled: false, source_ids: [] },
];
const sources = [
  { id: 1, source_type: 'gmail', identifier: 'one@example.com', updated_at: '2026-01-01T00:00:00Z' },
  { id: 2, source_type: 'gmail', identifier: 'two@example.com', updated_at: '2026-01-01T00:00:00Z' },
];

describe('UsersWorkspace', () => {
  it('lists users with their sources and binds a source on click', async () => {
    const requests: Request[] = [];
    const fetchFn = vi.fn<typeof fetch>(async (input) => {
      const request = input as Request;
      requests.push(request);
      const path = new URL(request.url).pathname;
      if (path === '/api/v1/users' && request.method === 'GET') return Response.json({ users });
      if (path === '/api/v1/sources/status') return Response.json({ sources });
      if (path === '/api/v1/users/7/sources' && request.method === 'PUT') {
        const body = (await request.clone().json()) as { source_ids: number[] };
        return Response.json({ ...users[0], source_ids: body.source_ids });
      }
      return Response.json({ error: 'not_found', message: 'nope' }, { status: 404 });
    });
    const session = createSessionController(fetchFn);
    render(UsersWorkspace, { client: session.client });

    await screen.findByText('Alice');
    const checkbox = screen.getByLabelText('alice@example.com sees two@example.com') as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect((screen.getByLabelText('root@example.com sees two@example.com') as HTMLInputElement).disabled).toBe(true);

    await fireEvent.click(checkbox);
    await waitFor(() => expect(requests.some((r) => r.method === 'PUT')).toBe(true));
    const put = requests.find((r) => r.method === 'PUT') as Request;
    expect(new URL(put.url).pathname).toBe('/api/v1/users/7/sources');
    await expect(put.clone().json()).resolves.toEqual({ source_ids: [1, 2] });
    await waitFor(() =>
      expect((screen.getByLabelText('alice@example.com sees two@example.com') as HTMLInputElement).checked).toBe(true),
    );
  });
});
