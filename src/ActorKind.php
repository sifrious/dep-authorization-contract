<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

enum ActorKind: string
{
    case Human = 'human';
    case Service = 'service';
    case Agent = 'agent';
    case System = 'system';
}
