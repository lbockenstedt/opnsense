<?php

namespace OPNsense\NetImpair;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->formDialogImpairment = $this->getForm("dialogImpairment");
        $this->view->pick('OPNsense/NetImpair/index');
    }
}
