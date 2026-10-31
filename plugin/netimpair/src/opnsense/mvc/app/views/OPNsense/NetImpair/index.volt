<script>
    $(document).ready(function () {
        $("#grid-impairments").UIBootgrid({
            search: '/api/netimpair/settings/search_impairment',
            get: '/api/netimpair/settings/get_impairment/',
            set: '/api/netimpair/settings/set_impairment/',
            add: '/api/netimpair/settings/add_impairment/',
            del: '/api/netimpair/settings/del_impairment/',
            toggle: '/api/netimpair/settings/toggle_impairment/'
        });
        $("#reconfigureAct").SimpleActionButton();
    });
</script>

<div class="content-box">
    <div class="col-md-12">
        <p>
            {{ lang._('Adds latency and packet loss to a Traffic Shaper pipe, like a pfSense limiter. Create the pipe under Pipes and send traffic into it with a rule under Rules, then impair it here.') }}
        </p>
    </div>
    <table id="grid-impairments" class="table table-condensed table-hover table-striped"
           data-editDialog="DialogImpairment" data-editAlert="impairmentChangeMessage">
        <thead>
        <tr>
            <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
            <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
            <th data-column-id="pipe" data-type="string">{{ lang._('Pipe') }}</th>
            <th data-column-id="delay" data-type="string">{{ lang._('Latency (ms)') }}</th>
            <th data-column-id="loss" data-type="string">{{ lang._('Packet loss (%)') }}</th>
            <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
            <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
        </tr>
        </thead>
        <tbody></tbody>
        <tfoot>
        <tr>
            <td></td>
            <td>
                <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span></button>
                <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
            </td>
        </tr>
        </tfoot>
    </table>
    <div class="col-md-12">
        <div id="impairmentChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing settings, please remember to apply them.') }}
        </div>
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/netimpair/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying the impairment') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogImpairment, 'id': 'DialogImpairment', 'label': lang._('Edit impairment')]) }}
