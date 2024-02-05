<?php

declare(strict_types = 1);

use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use Sop\X509\Certificate\Extension\NameConstraintsExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefNameConstraintsTest extends RefExtTestHelper
{
    /**
     * @return NameConstraintsExtension
     */
    public function testNameConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_NAME_CONSTRAINTS);
        $this->assertInstanceOf(NameConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testNameConstraintsExtension
     *
     * @return GeneralSubtrees
     */
    public function testNameConstraintPermittedSubtrees(
        NameConstraintsExtension $nc)
    {
        $subtrees = $nc->permittedSubtrees();
        $this->assertInstanceOf(GeneralSubtrees::class, $subtrees);
        return $subtrees;
    }

    /**
     * @depends testNameConstraintPermittedSubtrees
     */
    public function testNameConstraintPermittedDomain(GeneralSubtrees $gs)
    {
        $this->assertEquals('.example.com',
            $gs->all()[0]->base()
                ->name());
    }
}
