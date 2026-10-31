<?php

namespace OPNsense\NetImpair\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'netimpair';
    protected static $internalModelClass = 'OPNsense\NetImpair\NetImpair';

    public function searchImpairmentAction()
    {
        return $this->searchBase('impairments.impairment', ['enabled', 'pipe', 'delay', 'loss', 'description']);
    }

    public function getImpairmentAction($uuid = null)
    {
        return $this->getBase('impairment', 'impairments.impairment', $uuid);
    }

    public function addImpairmentAction()
    {
        return $this->addBase('impairment', 'impairments.impairment');
    }

    public function setImpairmentAction($uuid)
    {
        return $this->setBase('impairment', 'impairments.impairment', $uuid);
    }

    public function delImpairmentAction($uuid)
    {
        return $this->delBase('impairments.impairment', $uuid);
    }

    public function toggleImpairmentAction($uuid, $enabled = null)
    {
        return $this->toggleBase('impairments.impairment', $uuid, $enabled);
    }
}
