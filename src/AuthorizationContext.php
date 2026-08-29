<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

use InvalidArgumentException;
use JsonSerializable;
use Sifrious\ReferenceContract\CrossPackageReference;

final readonly class AuthorizationContext implements JsonSerializable
{
    public const CONTRACT = 'sifrious.authorization-context';
    public const CONTRACT_VERSION = 1;
    public function __construct(public ActorContext $actor, public TenantScope $tenant, public ?CrossPackageReference $correlation = null, public ?CrossPackageReference $provenance = null) {}
    /** @return array<string,mixed> */
    public function toArray(): array { return ['contract'=>self::CONTRACT,'contract_version'=>self::CONTRACT_VERSION,'actor'=>$this->actor->toArray(),'tenant'=>$this->tenant->toArray(),'correlation'=>$this->correlation?->toArray(),'provenance'=>$this->provenance?->toArray()]; }
    /** @param array<string,mixed> $value */
    public static function fromArray(array $value): self
    {
        if (($value['contract'] ?? null) !== self::CONTRACT || ($value['contract_version'] ?? null) !== self::CONTRACT_VERSION || ! is_array($value['actor'] ?? null) || ! is_array($value['tenant'] ?? null)) { throw new InvalidArgumentException('Unsupported authorization context contract or missing actor/tenant context.'); }
        return new self(ActorContext::fromArray($value['actor']), TenantScope::fromArray($value['tenant']), self::optionalReference($value, 'correlation'), self::optionalReference($value, 'provenance'));
    }
    /** @param array<string,mixed> $value */
    private static function optionalReference(array $value, string $key): ?CrossPackageReference
    {
        $reference = $value[$key] ?? null;
        if ($reference === null) { return null; }
        if (! is_array($reference)) { throw new InvalidArgumentException("{$key} must be a cross-package reference or null."); }
        return CrossPackageReference::fromArray($reference);
    }
    /** @return array<string,mixed> */
    public function jsonSerialize(): array { return $this->toArray(); }
}
