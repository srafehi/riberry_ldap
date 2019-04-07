from collections import defaultdict

from celery.utils.log import task_logger as log
from ldap3 import Server, Connection, NTLM, SIMPLE
from sqlalchemy.orm import subqueryload

from riberry import plugins, model, config
from riberry.celery import background
from riberry.plugins.interfaces import AuthenticationProvider


def synchronize():
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

    def find_users(self, distinguished_names):

        attributes = [v for v in self.config['user']['attributes']['additional'].values() if v]
        dns_joined = ''.join(
            f"({self.config['user']['attributes']['distinguishedName']}={dn})" for dn in distinguished_names)
        self.connection.search(
            search_base=self.config['user']['searchPath'],
            search_filter=f"(&"
                          f"(objectClass={self.config['user']['class']})"
                          f"(|{dns_joined})"
                          f"{self.config['user'].get('extraFilter') or ''}"
                          f")",
            attributes=attributes + [self.config['user']['attributes']['uniqueName'],
                                     self.config['user']['attributes']['distinguishedName']]
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


class LdapSynchronizationData:

    def __init__(self, users, groups, user_to_groups):
        self.users = users
        self.groups = groups
        self.user_to_groups = user_to_groups


class LdapAuthenticationProvider(AuthenticationProvider):

    @classmethod
    def name(cls) -> str:
        return 'ldap'

    @classmethod
    def _new_user(cls, username):
        user_model = model.auth.User(username=username, auth_provider=cls.name())
        model.conn.add(user_model)
        log.info(f'Created new user model for user {username!r}')
        return user_model

    @staticmethod
    def _new_group(group_name):
        group = model.group.Group(name=group_name)
        model.conn.add(group)
        log.info(f'Created new group {group!r}')
        return group

    @staticmethod
    def _new_user_group_association(user: model.auth.User, group: model.group.Group):
        association = model.group.ResourceGroupAssociation(
            group_id=group.id,
            resource_id=user.id,
            resource_type=model.misc.ResourceType.user,
        )
        model.conn.add(association)
        log.info(f'Associated user {user.username!r} to group {group.name!r}')
        return association

    @staticmethod
    def _delete_user_group_association(user: model.auth.User, group: model.group.Group):
        association: model.group.ResourceGroupAssociation = model.group.ResourceGroupAssociation.query().filter_by(
            group_id=group,
            resource_id=user.id,
            resource_type=model.misc.ResourceType.user,
        ).first()

        if association:
            model.conn.delete(association)
            user_model: model.auth.User = model.auth.User.query().filter_by(id=association.resource_id).first()
            user = user_model.username if user_model else association.resource_id
            log.info(f'Removed user {user!r} from group {association.group.name!r}')

    @staticmethod
    def _synchronize_user_model(user_model, user_data):
        if not user_model.details:
            user_model.details = model.auth.UserDetails(
                first_name=user_data.first_name or user_model.username,
                last_name=user_data.last_name or None,
                display_name=user_data.display_name or None,
                department=user_data.department or None,
                email=user_data.email or None
            )
        else:
            user_model.details.first_name = user_data.first_name or user_model.username
            user_model.details.last_name = user_data.last_name or None
            user_model.details.display_name = user_data.display_name or None
            user_model.details.department = user_data.department or None
            user_model.details.email = user_data.email or None

    @staticmethod
    def _load_ldap_data(manager) -> LdapSynchronizationData:
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
            users = manager.find_users(dns_partition)
            for user in users:
                ldap_user_group_mapping[user.username] = ldap_dns_group_mapping[user.distinguished_name]
                all_ldap_users.append(user)

        return LdapSynchronizationData(
            users=all_ldap_users,
            groups=all_ldap_groups,
            user_to_groups=ldap_user_group_mapping,
        )

    def load_manager(self):
        username, password = config.load_config_value(self.raw_config['credentials']).split(':', maxsplit=1)
        return LdapManager(user=username, password=password, config=self.raw_config)

    def authenticate(self, username: str, password: str) -> bool:
        manager = self.load_manager()

        try:
            user_data = manager.authenticate_user(username=username, password=password)
        except Exception as exc:
            log.info(f'LDAP user authentication failed with {type(exc).__name__} error: {exc}')
            return False

        user_model = model.auth.User.query().filter_by(username=user_data.username).first()
        if not user_model:
            user_model = self._new_user(username=user_data.username)

        self._synchronize_user_model(user_model=user_model, user_data=user_data)
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
            resource_type=model.misc.ResourceType.user
        ).all()

        user_model_mapping = {u.username: u for u in all_users}
        group_model_mapping = {g.name: g for g in all_groups}
        user_group_mapping = defaultdict(set)

        for association in all_user_group_mapping:
            user_group_mapping[association.resource_id].add(association.group_id)

        ldap_data = self._load_ldap_data(manager=manager)

        for ldap_group in ldap_data.groups:
            group = group_model_mapping.get(ldap_group.name)
            if not group:
                group = self._new_group(group_name=ldap_group.name)
                group_model_mapping[group.name] = group

        for ldap_user in ldap_data.users:
            user = user_model_mapping.get(ldap_user.username)
            if not user:
                user = self._new_user(username=ldap_user.username)
                user_model_mapping[user.username] = user

            self._synchronize_user_model(user_model=user, user_data=ldap_user)

        model.conn.commit()

        for username, group_names in ldap_data.user_to_groups.items():
            user = user_model_mapping[username]
            groups = {group_model_mapping[name] for name in group_names}

            for group in groups:
                if group.id not in user_group_mapping[user.id]:
                    self._new_user_group_association(user=user, group=group)

            group_ids = {group_model_mapping[name].id for name in group_names}
            for user_group in user_group_mapping[user.id]:
                if user_group not in group_ids:
                    self._delete_user_group_association(user=user, group=user_group)

        model.conn.commit()

    def secure_password(self, password: bytes) -> bytes:
        raise NotImplementedError

    def on_enabled(self):
        interval = self.raw_config.get('interval', 120)
        background.register_task('riberry_ldap:synchronize', schedule=interval)


plugins.plugin_register['authentication'].add(LdapAuthenticationProvider)
