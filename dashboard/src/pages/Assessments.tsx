import { Link } from "react-router";
import type { Assessment } from "../api";
import { can, useMe } from "../App";
import { useResource } from "../hooks";
import { Badge, PlannerLabel, StateView, When } from "../ui";

export function AssessmentsPage() {
  const me = useMe();
  const r = useResource<Assessment[]>("/assessments", 3000);
  return (
    <section>
      <div className="pagehead">
        <h1>Assessments</h1>
        {can(me, "operator")
          ? <Link className="btn primary" to="/assessments/new">New assessment</Link>
          : <span className="muted small">Creating assessments requires the operator role.</span>}
      </div>
      <StateView r={r} empty={(d) => d.length === 0} emptyText="No assessments yet. An operator can create one with an explicit, authorized scope.">
        {(rows) => (
          <div className="tablewrap"><table>
            <thead><tr><th>Name</th><th>Status</th><th>Planner</th><th>Findings</th><th>Pending approvals</th><th>Created</th><th>Finished</th></tr></thead>
            <tbody>{rows.map((a) => (
              <tr key={a.id}>
                <td><Link to={`/assessments/${a.id}`}>{a.name}</Link>{a.failure_reason && <div className="small bad">{a.failure_reason}</div>}</td>
                <td><Badge v={a.status} /></td>
                <td><PlannerLabel name={a.provider_name} live={a.provider_is_live_ai} /></td>
                <td>{a.findings}</td><td>{a.pending_approvals ? <Badge v="PENDING" /> : 0}</td>
                <td><When t={a.created_at} /></td><td><When t={a.finished_at} /></td>
              </tr>))}
            </tbody>
          </table></div>
        )}
      </StateView>
    </section>
  );
}
