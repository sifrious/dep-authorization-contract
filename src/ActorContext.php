<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

use InvalidArgumentException;
use JsonSerializable;
use Sifrious\ReferenceContract\CrossPackageReference;

final readonly class ActorContext implements JsonSerializable
{
    public const CONTRACT = 'sifrious.actor-context';
    public const CONTRACT_VERSION = 1;

    public function __construct(
        public CrossPackageReference $actor,
        public ActorKind $kind,
        public ?CrossPackageReference $actingFor = null,
        public ?CrossPackageReference $originatingService = null,
        public ?CrossPackageReference $provenance = null,
    ) {
        if ($kind === ActorKind::Human && $actingFor !== null) {
            throw new InvalidArgumentException('Human actors cannot silently impersonate another actor.');
        }
        if (in_array($kind, [ActorKind::Service, ActorKind::Agent], true) && $actingFor !== null && $actor->equals($actingFor)) {
            throw new InvalidArgumentException('Acting-for identity must differ from the service or agent actor.');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['contract'=>self::CONTRACT,'contract_version'=>self::CONTRACT_VERSION,'actor'=>$this->actor->toArray(),'kind'=>$this->kind->value,'acting_for'=>$this->actingFor?->toArray(),'originating_service'=>$this->originatingService?->toArray(),'provenance'=>$this->provenance?->toArray()];
    }
    /** @param array<string,mixed> $value */
    public static function fromArray(array $value): self
    {
        if (($value['contract'] ?? null) !== self::CONTRACT || ($value['contract_version'] ?? null) !== self::CONTRACT_VERSION) { throw new InvalidArgumentException('Unsupported actor context contract.'); }
        $actor = $value['actor'] ?? null;
        $kind = $value['kind'] ?? null;
        if (! is_array($actor) || ! is_string($kind) || ActorKind::tryFrom($kind) === null) { throw new InvalidArgumentException('Actor contexts require an actor reference and stable actor kind.'); }
        return new self(CrossPackageReference::fromArray($actor), ActorKind::from($kind), self::optionalReference($value, 'acting_for'), self::optionalReference($value, 'originating_service'), self::optionalReference($value, 'provenance'));
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
