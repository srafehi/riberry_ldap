from collections import defaultdict

from ldap3 import Server, Connection, NTLM, SIMPLE
from sqlalchemy.orm import subqueryload

from riberry import plugins, model, config
from riberry.celery import background
from riberry.plugins.interfaces import AuthenticationProvider


def sample_task():
    provider: LdapAuthenticationProvider = config.config.authentication["ldap"]
    provider.synchronize()


class UserData:

    def __init__(self, username, first_name, last_name, display_name, email, department, distinguished_name):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.display_name = display_name
        self.email = email
        self.department = department[0] if department and isinstance(department, tuple) else (department or None)
        self.distinguished_name = distinguished_name

    def __repr__(self):
        return f'<UserData username={self.username!r}>'


class GroupData:

    def __init__(self, name, label, description, distinguished_name, members=None):
        self.name = name
        self.label = label
        self.description = description
        self.distinguished_name = distinguished_name
        self.members = members or []

    def __repr__(self):
        return f'<GroupData name={self.name!r}>'


class LdapManager:

    def __init__(self, user, password, config):
        self.user = user
        self.password = password
        self.config = config
        self._server = None
        self._connection = None

    @property
    def server(self):
        if self._server is None:
            self._server = Server(self.config['server'], use_ssl=self.config.get('ssl'))
        return self._server

    @property
    def connection(self):
        if self._connection is None:
            self._connection = self.make_connection(self.server, self.user, self.password)
        return self._connection

    @staticmethod
    def make_connection(server, user, password, authentication=NTLM):
        conn = Connection(server, user=user, password=password, authentication=authentication)
        if not conn.bind():
            raise Exception('Invalid Credentials')
        return conn

    def authenticate_user(self, username, password):
        user = self.find_user(username)
        assert self.make_connection(self.server, user.distinguished_name, password, SIMPLE).bound
        return user

    def find_user2(self, dns):

        attributes = [v for v in self.config['user']['attributes']['additional'].values() if v]
        dns_joined = ''.join(f"({self.config['user']['attributes']['distinguishedName']}={dn})" for dn in dns)
        self.connection.search(
            search_base=self.config['user']['searchPath'],
            search_filter=f"(&"
                          f"(objectClass={self.config['user']['class']})"
                          f"(|{dns_joined})"
                          f"{self.config['user'].get('extraFilter') or ''}"
                          f")",
            attributes=attributes + [self.config['user']['attributes']['uniqueName'], self.config['user']['attributes']['distinguishedName']]
        )

        results = self.connection.response

        if not results:
            return []

        output = []
        for result in results:
            dn, user = result['dn'], result['attributes']
            user_data = UserData(
                username=self._load_attribute(user, 'user', 'uniqueName'),
                first_name=self._load_attribute(user, 'user', 'firstName'),
                last_name=self._load_attribute(user, 'user', 'lastName'),
                display_name=self._load_attribute(user, 'user', 'displayName'),
                email=self._load_attribute(user, 'user', 'email'),
                department=self._load_attribute(user, 'user', 'department'),
                distinguished_name=dn,
            )
            output.append(user_data)
        return output

    def find_user(self, username):

        attributes = [v for v in self.config['user']['attributes']['additional'].values() if v]
        self.connection.search(
            search_base=self.config['user']['searchPath'],
            search_filter=f"(&"
                          f"(objectClass={self.config['user']['class']})"
                          f"({self.config['user']['attributes']['uniqueName']}={username})"
                          f"{self.config['user'].get('extraFilter') or ''}"
                          f")",
            attributes=attributes + [self.config['user']['attributes']['uniqueName'],
                                     self.config['user']['attributes']['distinguishedName']]
        )

        results = self.connection.response

        if not results:
            return None

        if len(results) > 1:
            raise Exception('Found multiple users')

        result = results[0]
        dn, user = result['dn'], result['attributes']
        return UserData(
            username=self._load_attribute(user, 'user', 'uniqueName'),
            first_name=self._load_attribute(user, 'user', 'firstName'),
            last_name=self._load_attribute(user, 'user', 'lastName'),
            display_name=self._load_attribute(user, 'user', 'displayName'),
            email=self._load_attribute(user, 'user', 'email'),
            department=self._load_attribute(user, 'user', 'department'),
            distinguished_name=dn,
        )

    def _load_attribute(self, obj, type_, attribute, required=False):
        try:
            obj_attribute = self.config[type_]['attributes']['additional'][attribute]
        except KeyError:
            obj_attribute = self.config[type_]['attributes'][attribute]

        value = obj[obj_attribute] if obj_attribute else None
        if required and not value:
            raise Exception(f'{attribute!r}/{obj_attribute} is required, though value was None')
        return value

    def find_groups_for_user(self, user: UserData):
        attributes = [v for v in self.config['group']['attributes']['additional'].values() if v]
        self.connection.search(
            search_base=self.config['group']['searchPath'],
            search_filter=f"(&"
                          f"(objectClass={self.config['group']['class']})"
                          f"{self.config['group'].get('extraFilter') or ''}"
                          f"({self.config['group']['attributes']['membership']}={user.distinguished_name})"
                          f")",
            attributes=attributes + [self.config['group']['attributes']['uniqueName'],
                                     self.config['group']['attributes']['distinguishedName']]
        )
        groups = []
        for result in self.connection.response:
            dn, group = result['dn'], result['attributes']
            group_data = GroupData(
                name=group[self.config['group']['attributes']['uniqueName']],
                label=self._load_attribute(group, 'group', 'label'),
                description=self._load_attribute(group, 'group', 'description'),
                distinguished_name=dn,
            )
            groups.append(group_data)

        return groups

    def all_groups(self):
        attributes = [v for v in self.config['group']['attributes']['additional'].values() if v]
        self.connection.search(
            search_base=self.config['group']['searchPath'],
            search_filter=f"(&"
                          f"(objectClass={self.config['group']['class']})"
                          f"{self.config['group'].get('extraFilter') or ''}"
                          f")",
            attributes=attributes + [self.config['group']['attributes']['uniqueName'],
                                     self.config['group']['attributes']['distinguishedName'],
                                     self.config['group']['attributes']['membership']]
        )
        groups = []
        for result in self.connection.response:
            dn, group = result['dn'], result['attributes']
            group_data = GroupData(
                name=group[self.config['group']['attributes']['uniqueName']],
                label=self._load_attribute(group, 'group', 'label'),
                description=self._load_attribute(group, 'group', 'description'),
                distinguished_name=dn,
                members=group.get(self.config['group']['attributes']['membership'], [])
            )
            groups.append(group_data)

        return groups


class LdapAuthenticationProvider(AuthenticationProvider):

    @classmethod
    def name(cls) -> str:
        return 'ldap'

    def load_manager(self):
        username, password = config.load_config_value(self.raw_config['credentials']).split(':', maxsplit=1)
        return LdapManager(user=username, password=password, config=self.raw_config)

    def authenticate(self, username: str, password: str) -> bool:
        manager = self.load_manager()
        try:
            user_data = manager.authenticate_user(username=username, password=password)
        except:
            return False
        user_model = model.auth.User.query().filter_by(username=user_data.username).first()
        if not user_model:
            user_model = model.auth.User(
                username=user_data.username,
                auth_provider=self.name()
            )
            model.conn.add(user_model)

        if not user_model.details:
            user_model.details = model.auth.UserDetails(
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                display_name=user_data.display_name,
                department=user_data.department,
                email=user_data.email
            )
        else:
            user_model.details.first_name = user_data.first_name
            user_model.details.last_name = user_data.last_name
            user_model.details.display_name = user_data.display_name
            user_model.details.department = user_data.department
            user_model.details.email = user_data.email

        model.conn.commit()

        return True

    def synchronize(self):

        manager = self.load_manager()
        all_groups = model.group.Group.query().all()
        all_users = model.auth.User.query().filter_by(
            auth_provider=self.name()
        ).options(
            subqueryload(model.auth.User.details)
        ).all()
        all_user_group_mapping = model.group.ResourceGroupAssociation.query().filter_by(
            resource_type=model.group.ResourceType.user
        ).all()

        user_mapping = {u.username: u for u in all_users}
        group_mapping = {g.name: g for g in all_groups}
        user_group_mapping = defaultdict(set)

        for association in all_user_group_mapping:
            user_group_mapping[association.resource_id].add(association.group_id)

        all_ldap_groups = manager.all_groups()
        ldap_dns_group_mapping = defaultdict(set)
        for group in all_ldap_groups:
            for member in group.members:
                ldap_dns_group_mapping[member].add(group.name)

        all_ldap_dns = list(ldap_dns_group_mapping)
        all_ldap_users = []
        ldap_user_group_mapping = defaultdict(set)
        while all_ldap_dns:
            dns_partition, all_ldap_dns = all_ldap_dns[:500], all_ldap_dns[500:]
            users = manager.find_user2(dns_partition)
            for user in users:
                ldap_user_group_mapping[user.username] = ldap_dns_group_mapping[user.distinguished_name]
                all_ldap_users.append(user)

        for ldap_group in all_ldap_groups:
            group = group_mapping.get(ldap_group.name)
            if not group:
                group = model.group.Group(name=ldap_group.name)
                model.conn.add(group)
                group_mapping[group.name] = group

        for ldap_user in all_ldap_users:
            user = user_mapping.get(ldap_user.username)
            if not user:
                user = model.auth.User(
                    username=ldap_user.username,
                    auth_provider=self.name()
                )
                model.conn.add(user)
                user_mapping[user.username] = user

            if not user.details:
                user.details = model.auth.UserDetails(
                    first_name=ldap_user.first_name or user.username,
                    last_name=ldap_user.last_name or None,
                    display_name=ldap_user.display_name or None,
                    department=ldap_user.department or None,
                    email=ldap_user.email or None
                )
            else:
                user.details.first_name = ldap_user.first_name or user.username
                user.details.last_name = ldap_user.last_name or None
                user.details.display_name = ldap_user.display_name or None
                user.details.department = ldap_user.department or None
                user.details.email = ldap_user.email or None

        model.conn.commit()

        for username, group_names in ldap_user_group_mapping.items():
            user = user_mapping[username]
            groups = [group_mapping[name] for name in group_names]
            for group in groups:
                if group.id not in user_group_mapping[user.id]:
                    association = model.group.ResourceGroupAssociation(
                        group_id=group.id,
                        resource_id=user.id,
                        resource_type=model.group.ResourceType.user,
                    )
                    model.conn.add(association)

        model.conn.commit()

    def secure_password(self, password: bytes) -> bytes:
        raise NotImplementedError

    def on_enabled(self):
        background.register_task('riberry_ldap:sample_task', schedule=120)


plugins.plugin_register['authentication'].add(LdapAuthenticationProvider)
