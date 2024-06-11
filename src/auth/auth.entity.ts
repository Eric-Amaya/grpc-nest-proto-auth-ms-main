import { Exclude } from "class-transformer";
import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { Role } from "./enums/role.enum";

@Entity()
export class Auth extends BaseEntity {
    @PrimaryGeneratedColumn()
    public id!: number;

    @Column( {type: 'varchar'} )
    public email!: string;

    @Exclude()
    @Column( {type: 'varchar'} )
    public password!: string;

    @Column( {type: 'enum', default: Role.USER, enum: Role} )
    public role: Role;
}