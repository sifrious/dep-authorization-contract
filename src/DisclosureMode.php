<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

enum DisclosureMode: string
{
    case ExplicitForbidden = 'explicit_forbidden';
    case ConcealAsMissing = 'conceal_as_missing';
}
