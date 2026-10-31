<?php

namespace OPNsense\NetImpair\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    /**
     * Write our settings, then reload the Traffic Shaper pipes so the
     * loss/latency is applied to them (see scripts/OPNsense/NetImpair/dnctl).
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "failed"];
        }
        $backend = new Backend();
        $backend->configdRun('template reload OPNsense/NetImpair');
        $backend->configdRun('template reload OPNsense/Shaper');
        $result = trim($backend->configdRun('shaper reload'));
        if ($result != "OK") {
            return ["status" => "error reloading shaper (" . $result . ")"];
        }
        return ["status" => "ok"];
    }
}
